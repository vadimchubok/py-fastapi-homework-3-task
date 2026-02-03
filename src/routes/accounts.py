from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, models, UserGroupEnum
from config import get_jwt_auth_manager
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    MessageResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.passwords import hash_password, verify_password
from security.interfaces import JWTAuthManagerInterface

router = APIRouter(tags=["accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.UserModel).where(
            models.UserModel.email == user_data.email)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} "
                   f"already exists.",
        )

    try:
        user = models.UserModel(
            email=user_data.email,
            password=hash_password(user_data.password),
            group=UserGroupEnum.USER,
            is_active=False,
        )
        db.add(user)
        await db.flush()

        activation_token = models.ActivationTokenModel(
            user_id=cast(int, user.id)
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)
        return user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    token_result = await db.execute(
        select(models.ActivationTokenModel)
        .join(models.UserModel)
        .where(
            models.UserModel.email == data.email,
            models.ActivationTokenModel.token == data.token,
        )
    )
    token = token_result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime,
                      token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/",
             response_model=MessageResponseSchema)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(
            delete(models.PasswordResetTokenModel).where(
                models.PasswordResetTokenModel.user_id == user.id
            )
        )
        reset_token = models.PasswordResetTokenModel(
            user_id=cast(int, user.id)
        )
        db.add(reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an"
                       " email with instructions."}


@router.post("/reset-password/complete/",
             response_model=MessageResponseSchema)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(models.PasswordResetTokenModel)
        .join(models.UserModel)
        .where(
            models.UserModel.email == data.email,
            models.PasswordResetTokenModel.token == data.token,
        )
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    user = token.user
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = hash_password(data.password)
        await db.delete(token)
        await db.commit()
        return {"message": "Password reset successfully."}

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(
        select(models.UserModel).where(models.UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_manager.create_access_token(user.id)
        refresh_token = jwt_manager.create_refresh_token(user.id)

        models.RefreshTokenModel.create(
            db=db,
            user_id=cast(int, user.id),
            token=refresh_token,
        )
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    result = await db.execute(
        select(models.RefreshTokenModel).where(
            models.RefreshTokenModel.token == data.refresh_token
        )
    )
    stored_token = result.scalar_one_or_none()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_id = payload.get("sub")
    user = await db.get(models.UserModel, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(user.id)
    return {"access_token": access_token}

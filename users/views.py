from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiExample
from .serializers import (
    UserSerializer,
    UserCreateSerializer,
    UserUpdateSerializer,
    ChangePasswordSerializer
)

User = get_user_model()


@extend_schema_view(
    list=extend_schema(
        summary="List users",
        description="Get list of users. Regular users can only see their own profile. Admins see all users.",
        tags=["Users"]
    ),
    retrieve=extend_schema(
        summary="Get user details",
        description="Retrieve detailed information about a specific user.",
        tags=["Users"]
    ),
    create=extend_schema(
        summary="Register new user",
        description="Create a new user account. No authentication required.",
        tags=["Users"],
        examples=[
            OpenApiExample(
                'Registration Example',
                value={
                    'email': 'user@example.com',
                    'password': 'SecurePass123!',
                    'password_confirm': 'SecurePass123!',
                    'first_name': 'John',
                    'last_name': 'Doe'
                }
            )
        ]
    ),
    update=extend_schema(
        summary="Update user",
        description="Update user profile information.",
        tags=["Users"]
    ),
    partial_update=extend_schema(
        summary="Partially update user",
        description="Update specific fields of user profile.",
        tags=["Users"]
    ),
    destroy=extend_schema(
        summary="Delete user",
        description="Delete user account (admin only).",
        tags=["Users"]
    ),
)
class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for User CRUD operations.

    Provides endpoints for user registration, profile management, and authentication.
    """
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer

    def create(self, request, *args, **kwargs):
        """Registration is handled by the strict phone verification flow.

        This endpoint remains in the API surface for compatibility, but it must
        not create a User record before phone verification.
        """

        return Response(
            {
                'error': (
                    'Phone verification required before account creation. '
                    'Use /api/auth/signup/start/ and /api/auth/signup/confirm-phone/.'
                ),
            },
            status=status.HTTP_410_GONE,
        )

    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return super().get_permissions()

    def get_queryset(self):
        # Regular users can only see their own profile
        # Admins can see all users
        if self.request.user.is_admin or self.request.user.is_staff:
            return User.objects.all()
        return User.objects.filter(id=self.request.user.id)

    @extend_schema(
        summary="Get current user profile",
        description="Retrieve the profile of the currently authenticated user.",
        tags=["Users"],
        responses={200: UserSerializer}
    )
    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        """Get current user profile"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        summary="Change password",
        description="Change the password for the current user.",
        tags=["Users"],
        request=ChangePasswordSerializer,
        responses={200: {'type': 'object', 'properties': {'message': {'type': 'string'}}}},
        examples=[
            OpenApiExample(
                'Change Password Example',
                value={
                    'old_password': 'OldPass123!',
                    'new_password': 'NewSecurePass456!',
                    'new_password_confirm': 'NewSecurePass456!'
                }
            )
        ]
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def change_password(self, request):
        """Change user password"""
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @extend_schema(
        summary="Deactivate user account",
        description=(
            'Deactivate a user account. Users can deactivate their own account, '
            'admins can deactivate any account.'
        ),
        tags=["Users"],
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'message': {
                        'type': 'string',
                    },
                },
            },
        },
    )
    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def deactivate(self, request, pk=None):
        """Deactivate user account"""
        user = self.get_object()
        if request.user.id != user.id and not request.user.is_admin:
            return Response(
                {'error': 'You do not have permission to deactivate this user'},
                status=status.HTTP_403_FORBIDDEN
            )
        user.is_active = False
        user.save()
        return Response({'message': 'User deactivated successfully'}, status=status.HTTP_200_OK)

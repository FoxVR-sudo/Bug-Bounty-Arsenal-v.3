from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter
from .models import Plan, Subscription
from .serializers import (
    PlanSerializer,
    SubscriptionSerializer,
    SubscriptionUsageSerializer
)
from .stripe_utils import create_checkout_session, cancel_subscription, create_portal_session


class PlanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Plan CRUD operations
    """
    serializer_class = PlanSerializer
    queryset = Plan.objects.filter(is_active=True)
    filter_backends = [OrderingFilter]
    ordering_fields = ['price', 'created_at']
    ordering = ['price']

    def get_permissions(self):
        # Everyone can list and retrieve plans
        # Only admins can create, update, delete
        if self.action in ['list', 'retrieve']:
            return []
        return [IsAdminUser()]

    def get_queryset(self):
        # Non-admins only see active plans
        if self.request.user.is_authenticated and (self.request.user.is_admin or self.request.user.is_staff):
            return Plan.objects.all()
        return Plan.objects.filter(is_active=True)


class SubscriptionViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Subscription CRUD operations
    """
    serializer_class = SubscriptionSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['status']
    ordering_fields = ['created_at', 'current_period_end']
    ordering = ['-created_at']

    def get_queryset(self):
        # Users can only see their own subscriptions
        # Admins can see all subscriptions
        if self.request.user.is_admin or self.request.user.is_staff:
            return Subscription.objects.all()
        return Subscription.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Set the user from request
        serializer.save(user=self.request.user)

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def current(self, request):
        """Get current active subscription for user"""
        try:
            subscription = Subscription.objects.get(
                user=request.user,
                status='active'
            )
            serializer = SubscriptionUsageSerializer(subscription)
            return Response(serializer.data)
        except Subscription.DoesNotExist:
            return Response(
                {'error': 'No active subscription found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def usage(self, request):
        """Get usage statistics for current subscription"""
        try:
            subscription = Subscription.objects.get(
                user=request.user,
                status='active'
            )
            serializer = SubscriptionUsageSerializer(subscription)
            return Response(serializer.data)
        except Subscription.DoesNotExist:
            return Response(
                {'error': 'No active subscription found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def cancel(self, request, pk=None):
        """Cancel subscription (set cancel_at_period_end to True)"""
        subscription = self.get_object()
        subscription.cancel_at_period_end = True
        subscription.save()
        return Response(
            {'message': 'Subscription will be cancelled at period end'},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def reactivate(self, request, pk=None):
        """Reactivate subscription (set cancel_at_period_end to False)"""
        subscription = self.get_object()
        if subscription.status != 'active':
            return Response(
                {'error': 'Can only reactivate active subscriptions'},
                status=status.HTTP_400_BAD_REQUEST
            )
        subscription.cancel_at_period_end = False
        subscription.save()
        return Response(
            {'message': 'Subscription reactivated'},
            status=status.HTTP_200_OK
        )

    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def reset_usage(self, request, pk=None):
        """Reset daily usage for subscription (admin only)"""
        subscription = self.get_object()
        subscription.reset_daily_usage()
        return Response(
            {'message': 'Usage reset successfully'},
            status=status.HTTP_200_OK
        )

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def create_checkout(self, request):
        """Create Stripe checkout session for plan purchase"""
        plan_id = request.data.get('plan_id')
        billing_interval = request.data.get('billing_interval', 'month')

        if not plan_id:
            return Response(
                {'error': 'plan_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            plan = Plan.objects.get(id=plan_id, is_active=True)
        except Plan.DoesNotExist:
            return Response(
                {'error': 'Plan not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if user already has active subscription
        if Subscription.objects.filter(user=request.user, status='active').exists():
            return Response(
                {'error': 'You already have an active subscription'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create checkout session
        success_url = request.build_absolute_uri('/dashboard?payment=success')
        cancel_url = request.build_absolute_uri('/pricing?payment=canceled')

        try:
            session = create_checkout_session(
                user=request.user,
                plan=plan,
                success_url=success_url,
                cancel_url=cancel_url,
                billing_interval=billing_interval,
            )

            return Response({
                'checkout_url': session.url,
                'session_id': session.id
            })

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated])
    def cancel_stripe(self, request, pk=None):
        """Cancel subscription in Stripe"""
        subscription = self.get_object()

        try:
            cancel_subscription(subscription)
            return Response(
                {'message': 'Subscription canceled successfully'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def customer_portal(self, request):
        """Create Stripe Customer Portal session"""
        if not request.user.stripe_customer_id:
            return Response(
                {'error': 'No Stripe customer ID found'},
                status=status.HTTP_400_BAD_REQUEST
            )

        return_url = request.build_absolute_uri('/dashboard')

        try:
            portal_url = create_portal_session(
                customer_id=request.user.stripe_customer_id,
                return_url=return_url
            )

            return Response({'portal_url': portal_url})

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

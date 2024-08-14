from django.http import HttpResponse
from .serializers import RegisterSerializer ,LoginSerializer
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import User, Token  # Assuming these models are in the same app
from .serializers import UserSerializer
import uuid
from datetime import datetime, timedelta
from django.core.mail import send_mail
def home(request):
    return  HttpResponse("<h1>Hello from server</h1>")
# views.py


# class SignupView(APIView):
#     permission_classes = [AllowAny]
#     def post(self, request):
#         data = request.data
#         serializer = RegisterSerializer(data=data)
#
#         if not serializer.is_valid():
#             return Response(serializer.errors, status=400)
#
#         try:
#             user = serializer.save()
#             return Response({
#                 'message': 'User registered successfully',
#                 'user': {
#                     'username': user.username,
#                     'email': user.email,
#                     'contact_number': user.contact_number,
#                     'state': user.state,
#                 }
#             }, status=201)
#         except Exception as e:
#             return Response({'error': str(e)}, status=400)



class Loginuser(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            # Authenticate user
            user = User.objects.get(username=username)

            # Create or retrieve the token
            # Generate a new token key
            token_key = str(uuid.uuid4())

            # Try to find an existing token for the user
            token = Token.objects(user=user).first()

            if token:
                # Update the existing token
                token.key = token_key
                token.expires_at = datetime.utcnow() + timedelta(days=7)  # Reset expiration to 7 days
                token.save()
            else:
                # Create a new token
                token = Token(
                    user=user,
                    key=token_key,
                    expires_at=datetime.utcnow() + timedelta(days=7)  # Set expiration to 7 days
                )
                token.save()
            user = token.user
            # Retrieve the username
            username = user.username
            print(username)
            return Response({
                'message': 'Login successful',
                'token': token.key
            }, status=200)

        else:
            return Response(serializer.errors, status=400)




@csrf_exempt
def get_all_users(request):
    # Extract the token from the request headers
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return JsonResponse({'error': 'Authentication credentials were not provided.'}, status=401)

    try:
        # Token is typically in the format 'Token <token_key>', so split it
        token_key = auth_header.split(' ')[1]
    except IndexError:
        return JsonResponse({'error': 'Invalid token format.'}, status=401)

    # Retrieve the token document from the MongoDB database using mongoengine
    token = Token.objects(key=token_key).first()
    username = token.user.username
    print(username)

    if not token:
        return JsonResponse({'error': 'Invalid or expired token.'}, status=401)

    # Check if the token has expired
    if token.expires_at < datetime.utcnow():
        return JsonResponse({'error': 'Token has expired.'}, status=401)

    # If the token is valid, retrieve all users
    users = User.objects.all()
    serializer = UserSerializer(users, many=True)
    return JsonResponse(serializer.data, safe=False, status=200)





# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .models import User, OTP
from .serializers import RegisterSerializer, OTPSerializer, UserSerializer
import random
from django.core.mail import send_mail

class RegisterUserView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'error': 'All fields are required'}, status=400)

        data = serializer.validated_data
        if User.objects(email=data['email']).first() or User.objects(contact_number=data['contact_number']).first():
            return Response({'error': 'User with email or phone number already exists'}, status=409)

        otp_code = str(random.randint(100000, 999999))

        OTP.objects.create(email=data['email'], otp=otp_code)

        # Send OTP via email
        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp_code}. It will expire in 5 minutes.'
            f'jo me aatlu karyu have aakho project kari deje!',
            'your-email@example.com',  # Replace with your email
            [data['email']],
            fail_silently=False,
        )

        return Response({'message': 'OTP sent to your email'}, status=200)
import bcrypt

class VerifyOTPAndRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = OTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({'error': 'Invalid OTP or email'}, status=400)

        data = serializer.validated_data
        otp_record = OTP.objects(email=data['email'], otp=data['otp']).first()

        if not otp_record or otp_record.is_expired():
            return Response({'error': 'Invalid or expired OTP'}, status=400)

        # Remove the OTP after successful verification
        OTP.objects(email=data['email']).delete()
        hashed_password = bcrypt.hashpw(request.data['password'].encode('utf-8'), bcrypt.gensalt())
        user = User.objects.create(
            email=data['email'],
            contact_number=request.data['contact_number'],
            username=request.data['username'],
            password=hashed_password.decode('utf-8') , # Make sure to hash the password
            state=request.data['state']
        )

        user_data = UserSerializer(user).data

        return Response({'message': 'User registered successfully', 'user': user_data}, status=201)

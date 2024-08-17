
from django.http import HttpResponse
from .serializers import RegisterSerializer, LoginSerializer
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import User, Token
import uuid
import bcrypt
from .models import HiddenGem
from .serializers import HiddenGemSerializer
from django.http import Http404
from .models import Guide, CustomPackage, BookingHistory
from .serializers import GuideSerializer, CustomPackageSerializer, BookingHistorySerializer
from .permissions import IsAdminUser, IsAuthenticatedUser
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .models import User, OTP
from .serializers import RegisterSerializer, OTPSerializer, UserSerializer
import random
from django.core.mail import send_mail
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from mongoengine import DoesNotExist



def home(request):
    return HttpResponse("<h1>Hello from server</h1>")

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

    if token is None or token.user is None:
        return JsonResponse({'error': 'Invalid or expired token.'}, status=401)

    username = token.user.username

    # Check if the user has admin privileges
    if username == 'dungeon':
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return JsonResponse(serializer.data, safe=False, status=200)

    return JsonResponse({"error": "Only admin can access"}, status=401)


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
            f'',
            'Dungeon0559@gmail.com',  # Replace with your email
            [data['email']],
            fail_silently=False,
        )

        return Response({'message': 'OTP sent to your email'}, status=200)



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
            password=hashed_password.decode('utf-8'),  # Make sure to hash the password
            state=request.data['state']
        )

        user_data = UserSerializer(user).data

        return Response({'message': 'User registered successfully', 'user': user_data}, status=201)


# hidden gemss

class HiddenGemList(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        gems = HiddenGem.objects.all()
        serializer = HiddenGemSerializer(gems, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = HiddenGemSerializer(data=request.data)
        if serializer.is_valid():
            gem = serializer.save()
            return Response(HiddenGemSerializer(gem).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class HiddenGemDetail(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        try:
            return HiddenGem.objects.get(id=pk)
        except:
            return None

    def get(self, request, pk):
        gem = self.get_object(pk)
        if gem is None:
            return Response({"error": "Package not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = HiddenGemSerializer(gem)
        return Response(serializer.data)

    def patch(self, request, pk):
        self.permission_classes = [IsAdminUser]
        self.check_permissions(request)
        gem = self.get_object(pk)
        if gem is None:
            return Response({"error": "Package not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = HiddenGemSerializer(gem, data=request.data, partial=True)
        if serializer.is_valid():
            gem = serializer.save()
            return Response(HiddenGemSerializer(gem).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        self.permission_classes = [IsAdminUser]
        self.check_permissions(request)
        gem = self.get_object(pk)
        if gem is None:
            return Response({"error": "Package not found"}, status=status.HTTP_404_NOT_FOUND)
        gem.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# guide API


class GuideListCreateAPIView(APIView):
    permission_classes = [IsAuthenticatedUser]

    def get(self, request):
        """
        Retrieve all guides. Only accessible to admin users.
        """
        guides = Guide.objects.all()
        serializer = GuideSerializer(guides, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        self.permission_classes = [IsAdminUser]
        self.check_permissions(request)
        """
        Create a new guide. Only accessible to admin users.
        """
        serializer = GuideSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GuideDetailAPIView(APIView):
    permission_classes = [AllowAny]  # Only admin users can access this view

    def get_object(self, pk):
        try:
            return Guide.objects.get(pk=pk)
        except:
            raise Http404

    def get(self, request, pk):
        """
        Retrieve a specific guide by ID.
        """
        guide = self.get_object(pk)
        serializer = GuideSerializer(guide)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        self.permission_classes = [IsAdminUser]
        self.check_permissions(request)
        """
        Update a specific guide by ID.
        """
        guide = self.get_object(pk)
        serializer = GuideSerializer(guide, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        self.permission_classes = [IsAdminUser]
        self.check_permissions(request)
        """

        Delete a specific guide by ID.
        """
        guide = self.get_object(pk)
        guide.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# package API's

def serialize_custom_package(package):
    """Convert ObjectId fields to strings."""
    return {
        "id": str(package.id),
        "name": package.name,
        "places": [{"id": str(place.id), "name": place.name} for place in package.places],
        "state": package.state,
        "price": package.price,
        "number_of_persons": package.number_of_persons,
        "user": str(package.user.id),
        "booked_at": package.booked_at.isoformat(),
        "guide": str(package.guide.id) if package.guide else None
    }

class CreateCustomPackage(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request):
        user = request.user

        # Get data from the request
        place_ids = [place['id'] for place in request.data.get('places', [])]
        guide_id = request.data.get('guide')
        n = request.data.get('number_of_persons', 1)

        try:
            # Retrieve HiddenGems by IDs
            places = HiddenGem.objects.filter(id__in=place_ids)

            # Ensure that all selected places are in the same state
            if places:
                state = places.first().state  # Use the state of the first HiddenGem
                if not all(place.state == state for place in places):
                    return Response({"error": "All selected places must be in the same state."},
                                    status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"error": "No places selected or invalid place IDs."}, status=status.HTTP_400_BAD_REQUEST)


            guide = Guide.objects.get(id=guide_id) if guide_id else None


            total_price = sum([place.price for place in places])
            total_price *= n

            if guide:
                total_price += guide.price

            custom_package = CustomPackage.objects.create(
                name=request.data.get('name', 'Custom Package'),
                places=places,
                state=state,
                price=total_price,
                number_of_persons=n,
                user=user,  # Associate package with the user
                booked_at=datetime.utcnow(),
                guide=guide
            )

            # Add this package to the user's booking history
            booking_history_entry = BookingHistory(package=custom_package, guide=guide,
                                                   guide_price=guide.price if guide else 0)
            user.booking_history.append(booking_history_entry)
            user.save()

            # Serialize the response using the custom serializer
            serialized_package = serialize_custom_package(custom_package)
            return Response(serialized_package, status=status.HTTP_201_CREATED)

        except DoesNotExist:
            return Response({"error": "Guide or place not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Booking API's
class BookHiddenGem(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request):
        user = request.user
        gem_id = request.data.get('gem_id')
        number_of_persons = request.data.get('number_of_persons')  # Default to 1 person if not provided

        try:
            gem = HiddenGem.objects.get(id=gem_id)
            number_of_persons = int(number_of_persons)
            # Create a new booking history entry
            booking_history_entry = BookingHistory(
                gem=gem,
                booking_date=datetime.utcnow(),
                price=gem.price * number_of_persons,  # Calculate price based on the number of persons
                number_of_persons=number_of_persons
            )

            # Add the booking history entry to the user's booking history
            user.booking_history.append(booking_history_entry)
            user.save()

            # Update the number of person views in the HiddenGem
            gem.increment_person_views(number_of_persons)

            return Response({"message": "HiddenGem booked successfully!"}, status=status.HTTP_201_CREATED)

        except DoesNotExist:
            return Response({"error": "HiddenGem not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BookingHistoryView(APIView):
    permission_classes = [IsAuthenticatedUser]

    def get(self, request):
        user = request.user
        booking_history = user.booking_history

        if not booking_history:
            return Response({"message": "No booking history found."}, status=status.HTTP_404_NOT_FOUND)

        # Serialize the booking history
        serializer = BookingHistorySerializer(booking_history, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class BookCustomPackage(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request):
        user = request.user
        package_id = request.data.get('package_id')

        try:
            # Fetch the package
            package = CustomPackage.objects.get(id=package_id)

            # Optionally fetch the guide if provided
            guide = Guide.objects.get(id=request.data.get('guide_id')) if request.data.get('guide_id') else None

            # Get the number of persons from the package
            number_of_persons = package.number_of_persons

            # Create a booking history entry for the package
            booking_history_entry = BookingHistory(
                package=package,
                guide=guide,
                booking_date=datetime.utcnow(),
                price=package.price * number_of_persons,  # Calculate total price based on number of persons
                guide_price=(guide.price * number_of_persons) if guide else 0,
                number_of_persons=number_of_persons  # Store the number of persons in booking history
            )

            # Update the number of person views in each associated HiddenGem
            for gem in package.places:
                gem.number_of_person_views += number_of_persons
                gem.save()

            # Append the booking entry to the user's booking history
            user.booking_history.append(booking_history_entry)
            user.save()

            return Response({"message": "Custom Package booked successfully!"}, status=status.HTTP_201_CREATED)

        except DoesNotExist:
            return Response({"error": "Custom Package or Guide not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from django.http import HttpResponse
from .serializers import RegisterSerializer, LoginSerializer, DriverSerializer, CabSerializer
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import User, Token, Review, Driver, Cab
import uuid
import bcrypt
from .models import HiddenGem
from .serializers import HiddenGemSerializer ,ReviewSerializer
from django.http import Http404
from .models import Guide, CustomPackage, BookingHistory
from .serializers import GuideSerializer, CustomPackageSerializer, BookingHistorySerializer
from .permissions import IsAdminUser, IsAuthenticatedUser
from datetime import datetime, timedelta
from rest_framework.permissions import AllowAny
from .models import User, OTP
from .serializers import RegisterSerializer, OTPSerializer, UserSerializer
import random
from django.core.mail import send_mail
from datetime import datetime
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status



def home(request):
    return HttpResponse("<h1>Hello from server</h1>")

class Loginuser(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        print("123")
        from .serializers import LoginSerializer
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
        place_ids = request.data.get('places', [])
        guide_id = request.data.get('guide')
        number_of_persons = request.data.get('number_of_persons')  # Default to 1 if not provided

        # Ensure place_ids is a list of strings
        if not isinstance(place_ids, list):
            return Response({"error": "Invalid format for places."}, status=status.HTTP_400_BAD_REQUEST)

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

            # Retrieve the guide if provided
            guide = Guide.objects.get(id=guide_id) if guide_id else None

            # Calculate the total price
            total_price = sum([place.price for place in places])
            total_price *= number_of_persons

            if guide:
                total_price += guide.price

            # Create a new CustomPackage
            custom_package = CustomPackage(
                name=request.data.get('name', 'Custom Package'),
                places=places,
                state=state,
                price=total_price,
                number_of_persons=number_of_persons,
                user=user,  # Associate package with the user
                booked_at=now(),
                guide=guide
            )
            custom_package.save()


            serialized_package = serialize_custom_package(custom_package)
            return Response(serialized_package, status=status.HTTP_201_CREATED)

        except Guide.DoesNotExist:
            return Response({"error": "Guide not found."}, status=status.HTTP_404_NOT_FOUND)
        except HiddenGem.DoesNotExist:
            return Response({"error": "HiddenGem not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
from django.utils.timezone import now
from mongoengine import DoesNotExist

# Booking API's
class BookHiddenGem(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request):
        user = request.user
        gem_id = request.data.get('gem_id')
        number_of_persons = int(request.data.get('number_of_persons', 1))  # Default to 1 if not provided

        try:
            gem = HiddenGem.objects.get(id=gem_id)

            # Create a new booking history entry
            booking_history_entry = BookingHistory(
                user=user,
                gem=gem,
                booking_date=now(),
                price=gem.price * number_of_persons,
                number_of_persons=number_of_persons
            )
            booking_history_entry.save()

            # Optionally update the number of views in the HiddenGem
            gem.number_of_person_views += number_of_persons
            gem.save()

            # Fetch cab drivers in the same state
            cabs_in_state = Cab.objects.filter(state=gem.state, available=True)
            cab_details = CabSerializer(cabs_in_state, many=True).data

            # Fetch drivers associated with the cabs
            driver_ids = [cab.driver.id for cab in cabs_in_state if cab.driver]
            drivers = Driver.objects.filter(id__in=driver_ids)
            driver_details = DriverSerializer(drivers, many=True).data

            response_data = {
                "message": "HiddenGem booked successfully!",
                "cab_details": cab_details,
                "driver_details": driver_details
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        except HiddenGem.DoesNotExist:
            return Response({"error": "HiddenGem not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class BookCustomPackage(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request):
        user = request.user

        # Get data from the request
        package_id = request.data.get('package_id')
        number_of_persons = int(request.data.get('number_of_persons', 1))  # Default to 1 person if not provided

        try:
            # Retrieve the CustomPackage by ID
            custom_package = CustomPackage.objects.get(id=package_id)

            # Ensure that the number of persons is valid
            if number_of_persons <= 0:
                return Response({"error": "Number of persons must be greater than 0."}, status=status.HTTP_400_BAD_REQUEST)

            # Create a new booking history entry for the custom package
            booking_history_entry = BookingHistory(
                user=user,
                package=custom_package,
                guide=custom_package.guide,
                booking_date=now(),
                price=custom_package.price,
                number_of_persons=number_of_persons
            )
            booking_history_entry.save()

            # Fetch cab drivers in the same state
            state = custom_package.state
            if not state:
                return Response({"error": "Custom package state is not defined."}, status=status.HTTP_400_BAD_REQUEST)

            cabs_in_state = Cab.objects.filter(state=state, available=True)
            cab_details = CabSerializer(cabs_in_state, many=True).data

            # Fetch drivers associated with the cabs
            driver_ids = [cab.driver.id for cab in cabs_in_state if cab.driver]
            drivers = Driver.objects.filter(id__in=driver_ids)
            driver_details = DriverSerializer(drivers, many=True).data

            response_data = {
                "message": "Custom package booked successfully!",
                "package_details": serialize_custom_package(custom_package),
                "cab_details": cab_details,
                "driver_details": driver_details
            }

            return Response(response_data, status=status.HTTP_201_CREATED)

        except CustomPackage.DoesNotExist:
            return Response({"error": "CustomPackage not found."}, status=status.HTTP_404_NOT_FOUND)
        except DoesNotExist:
            return Response({"error": "Guide, cab, or driver not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

import json
from bson import ObjectId
class ReviewCreateAPIView(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request, *args, **kwargs):
        serializer = ReviewSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            review = serializer.save()
            # Convert all fields of the saved review to strings
            response_data = self.convert_to_string(serializer.data)
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def convert_to_string(self, data):
        """Recursively convert all values in a dictionary to strings."""
        if isinstance(data, dict):
            return {key: self.convert_to_string(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.convert_to_string(item) for item in data]
        elif isinstance(data, (bytes, ObjectId)):
            return str(data)
        elif isinstance(data, (int, float, bool)):
            return str(data)
        else:
            return data


class ReviewListAPIView(APIView):
    permission_classes = [IsAuthenticatedUser]

    def post(self, request, *args, **kwargs):
        place_id = request.data.get('place')

        if not place_id:
            return Response({'detail': 'Place ID is required in the request body.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Ensure place_id is a valid ObjectId
            place_id = ObjectId(place_id)
            place = HiddenGem.objects.get(id=place_id)
            reviews = Review.objects.filter(place=place)
        except:
            return Response({'detail': 'Place not found or invalid place ID.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = ReviewSerializer(reviews, many=True)
        response_data = self.convert_to_string(serializer.data)
        return Response(response_data)

    def convert_to_string(self, data):
        """Recursively convert all values in a dictionary to strings."""
        if isinstance(data, dict):
            return {key: self.convert_to_string(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.convert_to_string(item) for item in data]
        elif isinstance(data, (bytes, ObjectId)):
            return str(data)
        elif isinstance(data, (int, float, bool)):
            return str(data)
        else:
            return data


class DriverListCreateView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        drivers = Driver.objects.all()
        serializer = DriverSerializer(drivers, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = DriverSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DriverRetrieveUpdateDestroyView(APIView):
    def get_object(self, pk):
        try:
            return Driver.objects.get(id=pk)
        except DoesNotExist:
            return None

    def get(self, request, pk):
        driver = self.get_object(pk)
        if driver is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = DriverSerializer(driver)
        return Response(serializer.data)

    def put(self, request, pk):
        driver = self.get_object(pk)
        if driver is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = DriverSerializer(driver, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        driver = self.get_object(pk)
        if driver is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        driver.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CabListCreateView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        cabs = Cab.objects.all()
        serializer = CabSerializer(cabs, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = CabSerializer(data=request.data)
        if serializer.is_valid():
            driver_id = request.data.get('driver')

            # Fetch the driver to get the state
            if driver_id:
                try:
                    driver = Driver.objects.get(id=driver_id)
                    state = driver.state
                except Driver.DoesNotExist:
                    return Response({"error": "Driver does not exist."}, status=status.HTTP_400_BAD_REQUEST)

                # Add the state to the request data
                data = request.data.copy()
                data['state'] = state

                # Validate and save the cab with the updated state
                serializer_with_state = CabSerializer(data=data)
                if serializer_with_state.is_valid():
                    cab = serializer_with_state.save()

                    # Optionally, update the driver’s cabs list
                    driver.cabs.append(cab)
                    driver.save()

                    return Response(serializer_with_state.data, status=status.HTTP_201_CREATED)
                return Response(serializer_with_state.errors, status=status.HTTP_400_BAD_REQUEST)

            return Response({"error": "Driver ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class CabDetailView(APIView):
    permission_classes = [AllowAny]

    def get_object(self, pk):
        try:
            return Cab.objects.get(pk=pk)
        except DoesNotExist:
            return None

    def get(self, request, pk):
        cab = self.get_object(pk)
        if cab is None:
            return Response({"error": "Cab does not exist"}, status=status.HTTP_404_NOT_FOUND)
        serializer = CabSerializer(cab)
        return Response(serializer.data)

    def patch(self, request, pk):
        cab = self.get_object(pk)
        if cab is None:
            return Response({"error": "Cab does not exist"}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve and validate the data
        data = request.data.copy()
        driver_id = data.get('driver')

        if driver_id:
            try:
                driver = Driver.objects.get(id=driver_id)
                data['state'] = driver.state
            except Driver.DoesNotExist:
                return Response({"error": "Driver does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = CabSerializer(cab, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        cab = self.get_object(pk)
        if cab is None:
            return Response({"error": "Cab does not exist"}, status=status.HTTP_404_NOT_FOUND)
        cab.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class BookingHistoryListCreateView(APIView):
    permission_classes = [IsAuthenticatedUser]

    def get(self, request):
        user_id = request.user.id

        if not user_id:
            return Response({"error": "User ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve all booking history entries for the specified user
            bookings = BookingHistory.objects.filter(user=user_id)

            # Fetch additional details for each booking
            booking_details = []
            for booking in bookings:
                booking_data = {
                    "booking_id": str(booking.id),
                    "booking_date": booking.booking_date,
                    "price": booking.price,
                    "number_of_persons": booking.number_of_persons,
                    "gem": None,
                    "package": None,
                    "guide": None,
                    "cab": None,
                }

                # Fetch and add HiddenGem details if available
                if booking.gem:
                    gem = HiddenGem.objects.get(id=booking.gem.id)
                    booking_data["gem"] = {
                        "id": str(gem.id),
                        "name": gem.name,
                        "price": gem.price,
                        "state": gem.state
                    }

                # Fetch and add CustomPackage details if available
                if booking.package:
                    package = CustomPackage.objects.get(id=booking.package.id)
                    booking_data["package"] = {
                        "id": str(package.id),
                        "name": package.name,
                        "price": package.price,
                        "state": package.state,
                        "number_of_persons": package.number_of_persons,
                        "guide": {
                            "id": str(package.guide.id) if package.guide else None,
                            "name": package.guide.name if package.guide else None
                        } if package.guide else None
                    }

                # Fetch and add Cab details if available
                if booking.cab:
                    cab = Cab.objects.get(id=booking.cab.id)
                    booking_data["cab"] = {
                        "id": str(cab.id),
                        "car_name": cab.car_name,
                        "number_plate": cab.number_plate,
                        "number_of_persons": cab.number_of_persons,
                        "price": cab.price,
                        "available": cab.available,
                        "state": cab.state
                    }

                booking_details.append(booking_data)

            return Response(booking_details, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
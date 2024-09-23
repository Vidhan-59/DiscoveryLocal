import re
import bcrypt
from rest_framework import serializers
from .models import *
import bson
from .models import User
from django.contrib.auth.hashers import make_password
from .models import User  # Adjust the import according to your app structure

class ObjectIdField(serializers.Field):
    def to_representation(self, value):
        # Convert ObjectId to string for serialization
        return str(value) if isinstance(value, bson.ObjectId) else value

    def to_internal_value(self, data):
        # Convert string to ObjectId for deserialization
        return bson.ObjectId(data) if isinstance(data, str) else data


class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    password = serializers.CharField(max_length=100)
    contact_number = serializers.CharField(max_length=15)
    state = serializers.CharField(max_length=100)

    def validate(self, data):

        if User.objects(username=data['username']).first():
            raise serializers.ValidationError("Username already exists")


        if User.objects(email=data['email']).first():
            raise serializers.ValidationError("Email already exists")


        password = data['password']
        if len(password) < 6:
            raise serializers.ValidationError("Password must be at least 6 characters long")
        if not re.search(r'\d', password):
            raise serializers.ValidationError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError("Password must contain at least one special character")


        contact_number = data['contact_number']
        if not re.fullmatch(r'\d{10,15}', contact_number):
            raise serializers.ValidationError("Contact number must be between 10 and 15 digits long")

        return data




class UserSerializer(serializers.Serializer):
    id = ObjectIdField(read_only=True)  # Use CharField for ObjectId
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    contact_number = serializers.CharField(max_length=15)
    state = serializers.CharField(max_length=100)
    role = serializers.ChoiceField(choices=['ADMIN', 'GUIDE', 'USER'])
    profile_picture= serializers.URLField(read_only=True , required=False)
    # booking_history = serializers.ListField(child=serializers.DictField(), required=False)


class LoginSerializer(serializers.Serializer):
    print('123')
    username = serializers.CharField()
    password = serializers.CharField()
    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        # Authenticate user
        try:
            user = User.objects.get(username=username)
            print(user.username)
        except :
            raise serializers.ValidationError("Invalid username or password.")

        # Check if the password is correct
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            raise serializers.ValidationError("Invalid username or password.")

        return data



from rest_framework import serializers
from .models import HiddenGem

class HiddenGemSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)  # ObjectId will be handled automatically by MongoDB
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(allow_blank=True, required=False)
    state = serializers.CharField(max_length=100)
    photos = serializers.ListField(child=serializers.URLField(), allow_empty=True, required=False)
    rating = serializers.FloatField(min_value=0.0, max_value=5.0)  # Assuming rating is between 0 and 5
    number_of_person_views = serializers.IntegerField(default=0)
    price = serializers.FloatField(min_value=0.0)
    best_time = serializers.CharField(allow_blank=True, required=False)
    additional_info = serializers.CharField(allow_blank=True, required=False)
    category = serializers.ChoiceField(choices=HiddenGem.CATEGORY_CHOICES)

    def create(self, validated_data):
        """Create a new HiddenGem instance with validated data."""
        return HiddenGem.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """Update an existing HiddenGem instance."""
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


from rest_framework import serializers
from .models import Guide

class GuideSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()
    price = serializers.FloatField()
    available_dates = serializers.ListField(child=serializers.DateTimeField())
    def create(self, validated_data):
        return Guide.objects.create(**validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class CustomPackageSerializer(serializers.Serializer):
    id = serializers.CharField()
    name = serializers.CharField()
    places = HiddenGemSerializer(many=True)  # Assuming places is a list of HiddenGems
    state = serializers.CharField()
    price = serializers.FloatField()
    number_of_persons = serializers.IntegerField()
    booked_at = serializers.DateTimeField()
    guide = GuideSerializer()  # Assuming guide is optional


class BookingHistorySerializer(serializers.Serializer):

    package = CustomPackageSerializer()  # Include detailed package info
    gem = HiddenGemSerializer()  # Include gem details if applicable
    guide = serializers.CharField(source='guide.name', required=False)
    booking_date = serializers.DateTimeField()
    price = serializers.FloatField()
    guide_price = serializers.FloatField(required=False)
    number_of_persons = serializers.IntegerField(required=False)

    def get_gem(self, obj):
        if obj.gem:
            return HiddenGemSerializer(obj.gem).data
        return None

    def get_package(self, obj):
        if obj.package:
            return CustomPackageSerializer(obj.package).data
        return None

    def get_guide(self, obj):
        if obj.guide:
            return GuideSerializer(obj.guide).data
        return None



class ReviewSerializer(serializers.Serializer):
    user = serializers.PrimaryKeyRelatedField(read_only=True)  # Removed queryset
    place = serializers.PrimaryKeyRelatedField(queryset=HiddenGem.objects.all())
    comment = serializers.CharField(max_length=1000)
    rating = serializers.FloatField(min_value=0, max_value=5)
    created_at = serializers.DateTimeField(read_only=True)

    def create(self, validated_data):
        user = self.context['request'].user
        place = validated_data['place']

        # Check if the user can review the place
        if not Review.can_review(user, place):
            raise serializers.ValidationError("User has not booked this place and cannot leave a review.")

        review = Review(
            user=user,
            place=place,
            comment=validated_data['comment'],
            rating=validated_data['rating']
        )
        review.save()
        return review


class DriverSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)
    username = serializers.CharField(max_length=200)
    contact_number = serializers.CharField(max_length=15)
    state = serializers.CharField(max_length=100)
    available = serializers.BooleanField(default=True)
    password = serializers.CharField(max_length=10)
    role = serializers.CharField(default="DRIVER")
    cabs = serializers.ListField(child=serializers.CharField(), required=False)

    def create(self, validated_data):
        return Driver.objects.create(**validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
from bson import ObjectId
class CabSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True)
    driver = serializers.CharField()
    car_name = serializers.CharField(max_length=200)
    number_plate = serializers.CharField(max_length=20)
    number_of_persons = serializers.IntegerField()
    price = serializers.FloatField()
    available = serializers.BooleanField(default=True)
    state = serializers.CharField(max_length=100 ,required=False)

    def create(self, validated_data):
        return Cab.objects.create(**validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class BookingHistorySerializer(serializers.Serializer):
    user = UserSerializer()
    gem = HiddenGemSerializer()
    package = CustomPackageSerializer()
    guide = GuideSerializer()
    booking_date = serializers.DateTimeField()
    price = serializers.FloatField()
    number_of_persons = serializers.IntegerField()
    cab = CabSerializer()

    def create(self, validated_data):
        user_data = validated_data.pop('user', None)
        gem_data = validated_data.pop('gem', None)
        package_data = validated_data.pop('package', None)
        guide_data = validated_data.pop('guide', None)
        cab_data = validated_data.pop('cab', None)

        user = User.objects.get(id=user_data['id']) if user_data else None
        gem = HiddenGem.objects.get(id=gem_data['id']) if gem_data else None
        package = CustomPackage.objects.get(id=package_data['id']) if package_data else None
        guide = Guide.objects.get(id=guide_data['id']) if guide_data else None
        cab = Cab.objects.get(id=cab_data['id']) if cab_data else None

        booking = BookingHistory(
            user=user,
            gem=gem,
            package=package,
            guide=guide,
            cab=cab,
            **validated_data
        )
        booking.save()
        return booking

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        gem_data = validated_data.pop('gem', None)
        package_data = validated_data.pop('package', None)
        guide_data = validated_data.pop('guide', None)
        cab_data = validated_data.pop('cab', None)

        instance.user = User.objects.get(id=user_data['id']) if user_data else instance.user
        instance.gem = HiddenGem.objects.get(id=gem_data['id']) if gem_data else instance.gem
        instance.package = CustomPackage.objects.get(id=package_data['id']) if package_data else instance.package
        instance.guide = Guide.objects.get(id=guide_data['id']) if guide_data else instance.guide
        instance.cab = Cab.objects.get(id=cab_data['id']) if cab_data else instance.cab

        instance.booking_date = validated_data.get('booking_date', instance.booking_date)
        instance.price = validated_data.get('price', instance.price)
        instance.number_of_persons = validated_data.get('number_of_persons', instance.number_of_persons)
        instance.save()
        return instance


class TransactionSerializer(serializers.Serializer):
    booking_id = serializers.CharField(required=True)
    transaction_success = serializers.BooleanField(required=True)

    def validate(self, data):
        booking_id = data.get('booking_id')
        transaction_success = data.get('transaction_success')

        # Check if the booking exists
        try:
            booking = BookingHistory.objects.get(id=booking_id)
        except BookingHistory.DoesNotExist:
            raise serializers.ValidationError("Booking with this ID does not exist.")

        # Check if the transaction failed
        if not transaction_success:
            raise serializers.ValidationError("Transaction Failed.")

        return data

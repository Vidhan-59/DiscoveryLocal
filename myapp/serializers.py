import re
import bcrypt
from rest_framework import serializers
from .models import *
import bson

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


from rest_framework import serializers
from .models import User

from django.contrib.auth.hashers import make_password
from .models import User  # Adjust the import according to your app structure

class UserSerializer(serializers.Serializer):
    id = ObjectIdField(read_only=True)  # Use CharField for ObjectId
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    contact_number = serializers.CharField(max_length=15)
    state = serializers.CharField(max_length=100)
    role = serializers.ChoiceField(choices=['ADMIN', 'GUIDE', 'USER'])
    booking_history = serializers.ListField(child=serializers.DictField(), required=False)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        # Authenticate user
        try:
            user = User.objects.get(username=username)
        except :
            raise serializers.ValidationError("Invalid username or password.")

        # Check if the password is correct
        if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            raise serializers.ValidationError("Invalid username or password.")

        return data




class HiddenGemSerializer(serializers.Serializer):
    id = ObjectIdField(read_only=True)
    name = serializers.CharField(max_length=200)
    description = serializers.CharField(allow_blank=True)
    state = serializers.CharField(max_length=100)
    date = serializers.DateTimeField(required=False)
    photos = serializers.ListField(child=serializers.URLField(), required=False)
    rating = serializers.FloatField(required=False)
    number_of_person_views = serializers.IntegerField(required=False)
    price = serializers.FloatField(required=False)
    best_time = serializers.CharField(allow_blank=True)
    additional_info = serializers.CharField(allow_blank=True)

    def create(self, validated_data):
        return HiddenGem.objects.create(**validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
## delete

from rest_framework import serializers
from .models import Guide

class GuideSerializer(serializers.Serializer):
    id = ObjectIdField(read_only=True)
    name = serializers.CharField(max_length=200)
    price = serializers.FloatField()
    available_dates = serializers.ListField(child=serializers.DateTimeField(), required=False)

    def create(self, validated_data):
        return Guide.objects.create(**validated_data)

    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

class CustomPackageSerializer(serializers.Serializer):
    id = ObjectIdField(read_only=True)
    name = serializers.CharField(max_length=200)
    places = serializers.ListField(child=serializers.PrimaryKeyRelatedField(queryset=HiddenGem.objects.all()))
    state = serializers.CharField(max_length=100)
    price = serializers.FloatField()
    number_of_persons = serializers.IntegerField()
    guide = serializers.PrimaryKeyRelatedField(queryset=Guide.objects.all(), required=False)


class BookingHistorySerializer(serializers.Serializer):
    gem = serializers.CharField(source='gem.id', required=False)  # Convert ObjectId to string
    package = serializers.CharField(source='package.id', required=False)
    guide = serializers.CharField(source='guide.id', required=False)
    booking_date = serializers.DateTimeField()
    price = serializers.FloatField()
    guide_price = serializers.FloatField()

    # Optional: Include more detailed information if necessary
    gem_name = serializers.CharField(source='gem.name', required=False)
    package_name = serializers.CharField(source='package.name', required=False)
    guide_name = serializers.CharField(source='guide.name', required=False)



import re
import bcrypt
from rest_framework import serializers
from .models import *
import bson
from rest_framework import serializers
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
    # id = ObjectIdField(read_only=True)
    # name = serializers.CharField(max_length=200)
    # description = serializers.CharField(allow_blank=True)
    # state = serializers.CharField(max_length=100)
    # date = serializers.DateTimeField(required=False)
    # photos = serializers.ListField(child=serializers.URLField(), required=False)
    # rating = serializers.FloatField(required=False)
    # number_of_person_views = serializers.IntegerField(required=False)
    # price = serializers.FloatField(required=False)
    # best_time = serializers.CharField(allow_blank=True)
    # additional_info = serializers.CharField(allow_blank=True)

    id = serializers.CharField(allow_blank=True , required=False)
    name = serializers.CharField()
    description = serializers.CharField()
    state = serializers.CharField()
    date = serializers.DateTimeField()
    photos = serializers.ListField(child=serializers.URLField())
    rating = serializers.FloatField()
    number_of_person_views = serializers.IntegerField()
    price = serializers.FloatField()
    best_time = serializers.CharField()
    additional_info = serializers.CharField()
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
    # id = ObjectIdField(read_only=True)
    # name = serializers.CharField(max_length=200)
    # price = serializers.FloatField()
    # available_dates = serializers.ListField(child=serializers.DateTimeField(), required=False)
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
    # id = ObjectIdField(read_only=True)
    # name = serializers.CharField(max_length=200)
    # places = serializers.ListField(child=serializers.PrimaryKeyRelatedField(queryset=HiddenGem.objects.all()))
    # state = serializers.CharField(max_length=100)
    # price = serializers.FloatField()
    # number_of_persons = serializers.IntegerField()
    # guide = serializers.PrimaryKeyRelatedField(queryset=Guide.objects.all(), required=False)
    id = serializers.CharField()
    name = serializers.CharField()
    places = HiddenGemSerializer(many=True)  # Assuming places is a list of HiddenGems
    state = serializers.CharField()
    price = serializers.FloatField()
    number_of_persons = serializers.IntegerField()
    booked_at = serializers.DateTimeField()
    guide = GuideSerializer()  # Assuming guide is optional


class BookingHistorySerializer(serializers.Serializer):
    # gem = serializers.CharField(source='gem.id', required=False)  # Convert ObjectId to string
    # package = serializers.CharField(source='package.id', required=False)
    # guide = serializers.CharField(source='guide.id', required=False)
    # booking_date = serializers.DateTimeField()
    # price = serializers.FloatField()
    # guide_price = serializers.FloatField(required=False)
    # number_of_persons = serializers.IntegerField(required=False)  # Include the number of persons field
    #
    # # Additional details
    # gem_name = serializers.CharField(source='gem.name', required=False)
    # package_name = serializers.CharField(source='package.name', required=False)
    # guide_name = serializers.CharField(source='guide.name', required=False)
    # state = serializers.CharField(source='gem.state', required=False)  # Add state info from HiddenGem
    # rating = serializers.FloatField(source='gem.rating', required=False)  # Add rating from HiddenGem
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
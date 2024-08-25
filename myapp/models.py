import mongoengine as me
from datetime import datetime, timedelta

class HiddenGem(me.Document):
    name = me.StringField(required=True, max_length=200)
    description = me.StringField()
    state = me.StringField(required=True, max_length=100)
    date = me.DateTimeField()
    photos = me.ListField(me.URLField())
    rating = me.FloatField()
    number_of_person_views = me.IntField(default=0)  # Default to 0
    price = me.FloatField()
    best_time = me.StringField()
    additional_info = me.StringField()

    meta = {
        'collection': 'hidden_gems',
        'indexes': ['state', 'rating']
    }

    def increment_person_views(self, num_persons):
        self.number_of_person_views += num_persons
        self.save()


class Guide(me.Document):
    name = me.StringField(required=True, max_length=200)
    price = me.FloatField(required=True)
    available_dates = me.ListField(me.DateTimeField())  # Dates when the guide is available

    meta = {
        'collection': 'guides',
        'indexes': ['name', 'price']
    }


class CustomPackage(me.Document):
    name = me.StringField(required=True, max_length=200)
    places = me.ListField(me.ReferenceField(HiddenGem))
    state = me.StringField(required=True, max_length=100)
    price = me.FloatField()
    number_of_persons = me.IntField()
    user = me.ReferenceField('User')
    booked_at = me.DateTimeField(default=datetime.utcnow)
    guide = me.ReferenceField(Guide, null=True)  # Optional guide reference

    meta = {
        'collection': 'custom_packages'
    }


# class BookingHistory(me.EmbeddedDocument):
#     gem = me.ReferenceField(HiddenGem, null=True)
#     package = me.ReferenceField(CustomPackage, null=True)
#     guide = me.ReferenceField(Guide, null=True)
#     booking_date = me.DateTimeField(default=datetime.utcnow)
#     price = me.FloatField()
#     guide_price = me.FloatField()
#     number_of_persons = me.IntField(default=0)  # Field to store the number of persons booked



class User(me.Document):
    ROLE_CHOICES = ('ADMIN', 'GUIDE', 'USER')
    username = me.StringField(required=True, unique=True, max_length=100)
    email = me.EmailField(required=True, unique=True)
    password = me.StringField(required=True)
    contact_number = me.StringField(required=True, max_length=15)
    state = me.StringField(required=True, max_length=100)
    role = me.StringField(required=True, choices=ROLE_CHOICES, default='USER')  # Default role is 'normal_user'
    profile_picture = me.URLField(null=True ,required=False)
    # booking_history = me.EmbeddedDocumentListField('BookingHistory')
    meta = {
        'collection': 'users',
        'indexes': ['username', 'email']
    }

    def is_admin(self):
        return self.role == 'ADMIN'

    def is_guide(self):
        return self.role == 'GUIDE'

    def is_normal_user(self):
        return self.role == 'USER'


class OTP(me.Document):
    email = me.EmailField(required=True)
    otp = me.StringField(required=True)
    created_at = me.DateTimeField(default=datetime.utcnow)
    expires_at = me.DateTimeField(default=lambda: datetime.utcnow() + timedelta(minutes=5))

    meta = {
        'collection': 'otps',
        'indexes': ['email', 'otp', 'expires_at']
    }

    def is_expired(self):
        return self.expires_at < datetime.utcnow()


class Token(me.Document):
    user = me.ReferenceField(User, required=True)
    key = me.StringField(required=True, unique=True)
    created_at = me.DateTimeField(default=datetime.utcnow)
    expires_at = me.DateTimeField(default=lambda: datetime.utcnow() + timedelta(days=7))  # Token valid for 7 days by default

    meta = {
        'collection': 'tokens'
    }

    def is_valid(self):
        return self.expires_at > datetime.utcnow() if self.expires_at else True

class Review(me.Document):
    user = me.ReferenceField('User', required=True)
    place = me.ReferenceField(HiddenGem, required=True)
    comment = me.StringField(required=True, max_length=1000)
    rating = me.FloatField(min_value=0, max_value=5)
    created_at = me.DateTimeField(default=datetime.utcnow)

    meta = {
        'collection': 'reviews',
        'indexes': ['user', 'place', 'rating']
    }

    @classmethod
    def can_review(cls, user, place):
        """Check if the user can review the given place."""
        return any(
            history.gem == place for history in user.booking_history
        )
################################################################################################
class Driver(me.Document):
    username = me.StringField(required=True, max_length=200)
    contact_number = me.StringField(required=True, max_length=15)
    state = me.StringField(required=True, max_length=100)
    available = me.BooleanField(default=True)
    password = me.StringField(required=True, max_length=10)
    role = me.StringField(default="DRIVER", required=False)
    cabs = me.ListField(me.ReferenceField('Cab'), default=list)  # List of associated cabs

    meta = {
        'collection': 'drivers',
        'indexes': ['state', 'available']
    }

class Cab(me.Document):
    driver = me.ReferenceField(Driver, required=True)
    car_name = me.StringField(required=True, max_length=200)
    number_plate = me.StringField(required=True, max_length=20)
    number_of_persons = me.IntField(required=True)
    price = me.FloatField(required=True)
    available = me.BooleanField(default=True)
    state = me.StringField(required=True, max_length=100)

    meta = {
        'collection': 'cabs',
        'indexes': ['available']
    }



class BookingHistory(me.Document):
    user = me.ReferenceField(User, null=True)
    gem = me.ReferenceField(HiddenGem, null=True)
    package = me.ReferenceField(CustomPackage, null=True)
    guide = me.ReferenceField(Guide, null=True)
    booking_date = me.DateTimeField(default=datetime.utcnow)
    price = me.FloatField()
    number_of_persons = me.IntField(default=0)  # Field to store the number of persons booked
    cab=me.ReferenceField(Cab,null=True)
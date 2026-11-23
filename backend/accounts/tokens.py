from django.core import signing


class EmailVerificationToken:

    salt = 'accounts.email.verification'

    @classmethod
    def generate(cls, user):

        return signing.dumps(
            {'user_id': user.pk},
            salt=cls.salt
        )

    @classmethod
    def verify(cls, token):

        try:
            data = signing.loads(
                token,
                salt=cls.salt,
                max_age=60 * 60 * 24
            )

            return data.get('user_id')

        except signing.BadSignature:
            return None
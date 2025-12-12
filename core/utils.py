import random

def generate_code():
    return str(random.randint(100000, 999999))

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def get_device_name(request):
    ua = request.META.get('HTTP_USER_AGENT', '')
    return ua[:100]

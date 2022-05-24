# -*- coding: utf-8 -*-
import traceback
from rest_framework import viewsets, mixins, generics
from rest_framework.views import APIView, View
from rest_framework.response import Response
from rest_framework import authentication, permissions, status
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope, TokenHasScope
from django.shortcuts import render, HttpResponse, HttpResponseRedirect, resolve_url, redirect
from django.contrib.auth.models import User, Group
from django.contrib.auth.hashers import check_password, make_password
from django.conf import settings
from siteApp.serializers import UserSerializer, GroupSerializer
from django.core.serializers.json import json, DjangoJSONEncoder
from django.views.generic import *
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db.models import F
from python_http_client import exceptions 
from siteApp.models import *
from siteApp.serializers import *
import datetime 
import calendar
import time
import requests
import random
import string
import json
import os
import shutil
from django.urls import reverse
import decimal
from urllib.parse import urlencode
from django.contrib import messages

from oauth2_provider.settings import oauth2_settings
from oauth2_provider.models import (
	get_access_token_model, get_refresh_token_model,get_application_model
)
from oauthlib.oauth2.rfc6749.tokens import TokenBase, random_token_generator
from django.utils import timezone
from django.db.models import Q

import stripe

import sendgrid
from sendgrid.helpers.mail import Email, Substitution, Mail, Personalization 



#stripe.api_key = "sk_test_D97FSURZATTPQI40AYvGFHpU"
stripe.api_key = "sk_test_51DvBo8HwYPRN8kzUY9fLn5fXMpdRRgfKyO45YPrJnLEQRaK6lEHZpm9Jq17P44wPg95yFfEpSTivkscI4qD8NMTy00vNnTzJHn"
#Stripe_Pub_key = "pk_test_zJ7GSTlq3evk1L21dmhpfAcq"

AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()
Application = get_application_model()

#google client
api_client_id = 'x4ahpCqVHTL71MXOTFWdrcynBGZiwgIACCOxeu6e'
api_client_secret = 'coh8MlDo6onTzhYqs4V5RGuTnXToojckDiThDPbk5kxUKSrF4U2qACIu4paXLjfrQUHcCAxURV1nQWk9yS0VqLXVqZCSNBQt6w8eI5MQ9abjSp64fPgVqGhPtdUrJOqm'

#Zoho Details
#ZOHO_CLIENT_ID = "1000.DL8VZCO7DRECZP9DPH96QEGRN108YU"
#ZOHO_CLIENT_SECRET = "3f39da7a0f41dd80cc29f148c3db07252aa74cc4db"
ZOHO_CLIENT_ID = "1000.QVTM7QYG67JKTO6HWLNGZ6HV0KK3IB"
ZOHO_CLIENT_SECRET = "f832eeb9d709d2ad8bf6f5209da1c6a74cfdde5f49"
ZOHO_REDIRECT_URI = "http://159.65.145.117/zoho-token" 
Zoho_Subscriptions_OrgID = "733685323"
# Zoho_Desk_OrgID = "743184512"
Zoho_Desk_OrgID = "733785182"
Zoho_Refersh_Token_Url = "https://accounts.zoho.com/oauth/v2/token"
Zoho_Subscription_Url = "https://subscriptions.zoho.com/api/v1/subscriptions"

country_phone_codes = {"BD": "880", "BE": "32", "BF": "226", "BG": "359", "BA": "387", "BB": "+1-246", "WF": "681", "BL": "590", "BM": "+1-441", "BN": "673", "BO": "591", "BH": "973", "BI": "257", "BJ": "229", "BT": "975", "JM": "+1-876", "BV": "", "BW": "267", "WS": "685", "BQ": "599", "BR": "55", "BS": "+1-242", "JE": "+44-1534", "BY": "375", "BZ": "501", "RU": "7", "RW": "250", "RS": "381", "TL": "670", "RE": "262", "TM": "993", "TJ": "992", "RO": "40", "TK": "690", "GW": "245", "GU": "+1-671", "GT": "502", "GS": "", "GR": "30", "GQ": "240", "GP": "590", "JP": "81", "GY": "592", "GG": "+44-1481", "GF": "594", "GE": "995", "GD": "+1-473", "GB": "44", "GA": "241", "SV": "503", "GN": "224", "GM": "220", "GL": "299", "GI": "350", "GH": "233", "OM": "968", "TN": "216", "JO": "962", "HR": "385", "HT": "509", "HU": "36", "HK": "852", "HN": "504", "HM": " ", "VE": "58", "PR": "+1-787 and 1-939", "PS": "970", "PW": "680", "PT": "351", "SJ": "47", "PY": "595", "IQ": "964", "PA": "507", "PF": "689", "PG": "675", "PE": "51", "PK": "92", "PH": "63", "PN": "870", "PL": "48", "PM": "508", "ZM": "260", "EH": "212", "EE": "372", "EG": "20", "ZA": "27", "EC": "593", "IT": "39", "VN": "84", "SB": "677", "ET": "251", "SO": "252", "ZW": "263", "SA": "966", "ES": "34", "ER": "291", "ME": "382", "MD": "373", "MG": "261", "MF": "590", "MA": "212", "MC": "377", "UZ": "998", "MM": "95", "ML": "223", "MO": "853", "MN": "976", "MH": "692", "MK": "389", "MU": "230", "MT": "356", "MW": "265", "MV": "960", "MQ": "596", "MP": "+1-670", "MS": "+1-664", "MR": "222", "IM": "+44-1624", "UG": "256", "TZ": "255", "MY": "60", "MX": "52", "IL": "972", "FR": "33", "IO": "246", "SH": "290", "FI": "358", "FJ": "679", "FK": "500", "FM": "691", "FO": "298", "NI": "505", "NL": "31", "NO": "47", "NA": "264", "VU": "678", "NC": "687", "NE": "227", "NF": "672", "NG": "234", "NZ": "64", "NP": "977", "NR": "674", "NU": "683", "CK": "682", "XK": "", "CI": "225", "CH": "41", "CO": "57", "CN": "86", "CM": "237", "CL": "56", "CC": "61", "CA": "1", "CG": "242", "CF": "236", "CD": "243", "CZ": "420", "CY": "357", "CX": "61", "CR": "506", "CW": "599", "CV": "238", "CU": "53", "SZ": "268", "SY": "963", "SX": "599", "KG": "996", "KE": "254", "SS": "211", "SR": "597", "KI": "686", "KH": "855", "KN": "+1-869", "KM": "269", "ST": "239", "SK": "421", "KR": "82", "SI": "386", "KP": "850", "KW": "965", "SN": "221", "SM": "378", "SL": "232", "SC": "248", "KZ": "7", "KY": "+1-345", "SG": "65", "SE": "46", "SD": "249", "DO": "+1-809 and 1-829", "DM": "+1-767", "DJ": "253", "DK": "45", "VG": "+1-284", "DE": "49", "YE": "967", "DZ": "213", "US": "1", "UY": "598", "YT": "262", "UM": "1", "LB": "961", "LC": "+1-758", "LA": "856", "TV": "688", "TW": "886", "TT": "+1-868", "TR": "90", "LK": "94", "LI": "423", "LV": "371", "TO": "676", "LT": "370", "LU": "352", "LR": "231", "LS": "266", "TH": "66", "TF": "", "TG": "228", "TD": "235", "TC": "+1-649", "LY": "218", "VA": "379", "VC": "+1-784", "AE": "971", "AD": "376", "AG": "+1-268", "AF": "93", "AI": "+1-264", "VI": "+1-340", "IS": "354", "IR": "98", "AM": "374", "AL": "355", "AO": "244", "AQ": "", "AS": "+1-684", "AR": "54", "AU": "61", "AT": "43", "AW": "297", "IN": "91", "AX": "+358-18", "AZ": "994", "IE": "353", "ID": "62", "UA": "380", "QA": "974", "MZ": "258"}


def logError(e):
	f = open('/var/www/siteSeedApi/errorlog.txt','a')
	error = str(e)+"\n"
	f.write(error)
	f.close()

def baseB64Encode(data):
	return base64.b64encode(bytes(data, 'utf-8')).decode('ascii')

def baseB64Decode(data):
	return base64.b64decode(bytes(data, 'utf-8')).decode('ascii')

def Handle_404_Error(request):
	final_response = {}
	final_response['status'] = status.HTTP_404_NOT_FOUND	
	final_response['message'] = "Page not found!"
	
	return HttpResponse(json.dumps(final_response), content_type='application/json')

def func_phone_format(n):
    return format(int(n[:-1]), ",").replace(",", "-") + n[-1]


class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    permission_classes = [ TokenHasReadWriteScope]
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    permission_classes = [ TokenHasReadWriteScope]
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


"""
Google Authentication
"""
def google_login(request):
	
    redirect_uri = "%s://%s%s" % (request.scheme, request.get_host(), reverse('google-login'))
    
    if('code' in request.GET):
        params = {
            'grant_type': 'authorization_code',
            'code': request.GET.get('code'),
            'redirect_uri': redirect_uri,
            'client_id': settings.GP_CLIENT_ID,
            'client_secret': settings.GP_CLIENT_SECRET
        }
        url = 'https://accounts.google.com/o/oauth2/token'
        response = requests.post(url, data=params)
        url = 'https://www.googleapis.com/oauth2/v1/userinfo'
        access_token = response.json().get('access_token')
        response = requests.get(url, params={'access_token': access_token})
        user_data = response.json()
        email = user_data.get('email')
        if email:
			
            user = User.objects.get_or_create(email=email, username=email)
            gender = user_data.get('gender', '').lower()
            if gender == 'male':
                gender = 'M'
            elif gender == 'female':
                gender = 'F'
            else:
                gender = 'O'
            data = {
                'first_name': user_data.get('name', '').split()[0],
                'last_name': user_data.get('family_name'),
                'google_avatar': user_data.get('picture'),
                'gender': gender,
                'is_active': True
            }
            # ~ user.first_name=data['first_name']
            # ~ user.last_name= data['last_name']
            # ~ user.save()
            
            if data['first_name'] != "":
                user_update = User.objects.get(email=email)
                user_update.first_name =  str(data['first_name'])
                user_update.last_name = str(data['last_name'])
                user_update.save()
			
            expire_seconds = settings.ACCESS_TOKEN_EXPIRE_SECONDS
            scopes = 'read write'
            application = Application.objects.get(name="siteSeedApi")
            expires = timezone.now() + datetime.timedelta(seconds=expire_seconds)
            user = User.objects.get(email=str(email))
            access_token = AccessToken.objects.create(user=user,application=application,token=random_token_generator(request),expires=expires,scope=scopes)

            refresh_token = RefreshToken.objects.create(user=user,token=random_token_generator(request),access_token=access_token,application=application)
            message = {
            'access_token': access_token.token,
			'token_type': 'Bearer',
			'expires_in': expire_seconds,
			'refresh_token': refresh_token.token,
			'email': email,
			'scope': scopes}
            return HttpResponse(str(message))

            return HttpResponse(json.dumps(final_response))            
            
            return HttpResponse(str(data))
            login(request, user)
        else:
            messages.error(
                request,
                'Unable to login with Gmail Please try again'
            )
        return redirect('/')
    else:
        url = "https://accounts.google.com/o/oauth2/auth?client_id=%s&response_type=code&scope=%s&redirect_uri=%s&state=google"
        scope = [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email"
        ]
        scope = " ".join(scope)
        url = url % (settings.GP_CLIENT_ID, scope, redirect_uri)
        return redirect(url)


"""
Authenticate the user via email and password
"""
@csrf_exempt
def emailAuth(request):
	final_response = {}

	if request.method == "POST":
		post_data = json.loads(request.body)
		email = post_data['email']
		password = post_data['password']
		try:	 
			user_data = custMaster.objects.get(email=email)
			email = user_data.email
			custID = user_data.cust_id
			first_name = user_data.first_name
			last_name = user_data.last_name
			phone = user_data.phone
			display_name = user_data.display_name
			bio = user_data.bio
			profile_pic = user_data.profile_picture.url
			
			url = str(settings.TOKEN_URL)+'/o/token/'
				
			cleaned_data = {}
			cleaned_data['username'] = str(email)
			cleaned_data['password'] = str(password)
			cleaned_data['client_id'] = api_client_id
			cleaned_data['client_secret'] = api_client_secret
			cleaned_data['grant_type'] = 'password'
				
			req = requests.post(url, data=cleaned_data)
			req_data = req.json()


			if "Invalid credentials given" in str(req_data):
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['messageType'] = "error"		
				final_response['message'] = "Invalid credentials"
				return HttpResponse(json.dumps(final_response), content_type='application/json')
				
			messageType = "success"
			message = "success"
			final_response['token_information'] = req_data
			final_response['userinfo'] = {"custID":custID, "phone":phone, "first_name":first_name, 'last_name':last_name, 'email':email, 'display_name':display_name, 'bio':bio, 'profile_picture':profile_pic}
			final_response['messageType'] = messageType		
			final_response['message'] = message	
			final_response['status'] = status.HTTP_200_OK

			return HttpResponse(json.dumps(final_response), content_type='application/json')

		except Exception as e:
			final_response['status'] = status.HTTP_500_INTERNAL_SERVER_ERROR	
			final_response['messageType'] = "error"		
			final_response['message'] = "Invalid email or password."+ str(e)
			return HttpResponse(json.dumps(final_response), content_type='application/json')
	

"""
Authenticate the user via email and password
"""
@csrf_exempt
def forgotPassword(request):
	"""
	* Sending forgot password email
	"""		
	
	final_response={}
	if request.method == "POST":
		try:
			post_data = json.loads(request.body)
			email = post_data["email"]
			
			random_number =random.SystemRandom().randint(100000,999999)
			
			try:
				check_user = custMaster.objects.get(email=email)
				# ~ subject = 'Password Reset' 
				# ~ message = 'Here is the forgot password OTP - '+str(random_number) 
				# ~ email_from = settings.EMAIL_HOST_USER 
				# ~ recipient_list = email
				# ~ send_mail(subject, message, email_from, [recipient_list])
				
				sg = sendgrid.SendGridAPIClient(api_key=str(settings.SENDGRID_API_KEY)) 
				personalization = Personalization() 
				personalization.add_to(Email(str(email))) 
				personalization.dynamic_template_data={"OTP":str(random_number)}
				mail = Mail() 
				mail.from_email = Email(str(settings.SENDGRID_FROM_EMAIL)) 
				mail.subject = "Forgot password OTP" 
				mail.add_personalization(personalization) 
				mail.template_id = "d-08442d1e4ac342b1bf7cb84f29eed285" 
				try:
					response = sg.client.mail.send.post(request_body=mail.get())
					resposne_array = response.headers
				except exceptions.BadRequestsError as e:
					# ~ return HttpResponse(str(e.body))
					resposne_array = str(e.body)
					
				check_user.forgot_pswd_status = str(random_number)
				check_user.save()
					
				final_response['otp'] = str(random_number)		
				final_response['messageType'] = "success"		
				final_response['status'] = status.HTTP_200_OK
				final_response['message'] = "Forgot password OTP sent in your email."

			except Exception as e:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['messageType'] = "error"		
				final_response['message'] = "Invalid email account. "+ str(e)
				return HttpResponse(json.dumps(final_response))
				
		except Exception as e:
			final_response['status'] = status.HTTP_500_INTERNAL_SERVER_ERROR	
			final_response['messageType'] = "error"		
			final_response['message'] = "Error in request. "+ str(e)
			return HttpResponse(json.dumps(final_response))
		
	return HttpResponse(json.dumps(final_response), content_type='application/json')


@csrf_exempt
def resetPassword(request):
	"""
	* Update reset password using otp.
	"""		
	final_response={}
	if request.method == "POST":
		try:
			post_data = json.loads(request.body)
			email = post_data["email"]
			otp = post_data["otp"]
			new_password = post_data["new_password"]
			
			random_number =random.SystemRandom().randint(100000,999999)
			
			try:
				check_user = custMaster.objects.get(email=email)
				otp_code = check_user.forgot_pswd_status
				if str(otp_code) == str(otp):
					check_user.forgot_pswd_status = 0
					check_user.save()
					
					u = User.objects.get(username=str(email))
					u.set_password(str(new_password))
					u.save()
					
					final_response['messageType'] = "success"
					final_response['status'] = status.HTTP_200_OK
					final_response['message'] = "Password successfully changed."
					return HttpResponse(json.dumps(final_response), content_type='application/json')

				final_response['otp'] = str(random_number)		
				final_response['messageType'] = "warning"		
				final_response['status'] = status.HTTP_400_BAD_REQUEST
				final_response['message'] = "OTP did no matched."
				return HttpResponse(json.dumps(final_response), content_type='application/json')

			except Exception as e:
				final_response['messageType'] = "warning"		
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = str(e)
				
		except Exception as e:
			final_response['status'] = status.HTTP_500_INTERNAL_SERVER_ERROR	
			final_response['messageType'] = "error"		
			final_response['message'] = "Error in request. "+ str(e)
			return HttpResponse(json.dumps(final_response))
		
	return HttpResponse(json.dumps(final_response), content_type='application/json')

############################################### Zoho Utility functions ##########################################################
# Zoho redirect uri function
class zohoGrantToken(View):

	def get(self, request, format=None):
		
		return HttpResponse(request.GET)
		
	def post(self, request, format=None):
		return HttpResponse(json.dumps(request.body), content_type='application/json')

# Refresh Zoho token if expired
def RefreshZohoToken():
	try:
		zoho_token = zohoAuthToken.objects.get(id=1)
		z_refresh_token = zoho_token.refresh_token

		payload={'refresh_token': z_refresh_token,
		'client_id': ZOHO_CLIENT_ID,
		'client_secret': ZOHO_CLIENT_SECRET,
		'redirect_uri': ZOHO_REDIRECT_URI,
		'grant_type': 'refresh_token'}

		response = requests.request("POST", Zoho_Refersh_Token_Url, data=payload)
		token_data = response.json()
		zoho_token.access_token = token_data['access_token']
		zoho_token.updatedOn = datetime.datetime.now()
		zoho_token.save()
		try:
			access_token = str(token_data['access_token'])
			return access_token
		except Exception:
			return token_data	
	except Exception as e:
		return "Error in api. " +str(e)

# Add user to Zoho subscription
def zohoSubscription(user_id, firstName, lastName, email, subscription_plan_id=1):
	try:
		display_name = firstName+lastName
		starts_at = str(datetime.date.today())
		
		zoho_token = zohoAuthToken.objects.get(id=1)
		z_authorization = 'Zoho-oauthtoken ' + str(zoho_token.access_token)

		payload="{\n\t\"customer\": {\n\t\t\"display_name\": \""+display_name+"\",\n\t\t\"first_name\": \""+firstName+"\",\n\t\t\"last_name\": \""+lastName+"\",\n\t\t\"email\": \""+email+"\"\n\t},\n\t\"starts_at\": \""+starts_at+"\",\n\t\"plan\": {\n\t\t\"plan_code\": \"ss_free\",\n\t\t\"plan_description\": \"free plan\",\n\t\t\"quantity\": \"1\",\n\t\t\"setup_fee\": \"0.00\"\n\t},\n\t\"payment_terms\": 0,\n\t\"payment_terms_label\": \"Due on Receipt\",\n\t\"auto_collect\": false,\n\t\"reference_id\": \"ss_free_plan\"\n}"
		headers = {
		'X-com-zoho-subscriptions-organizationid': Zoho_Subscriptions_OrgID,
		'Authorization': z_authorization,
		'Content-Type': 'application/json'
		}
		response = requests.request("POST", Zoho_Subscription_Url, headers=headers, data=payload)
		json_resp = response.json()
		if "Subscription has been created successfully." in json_resp['message']:
			# add subscription plan with default plan id ss_free
			subscription_id = json_resp['subscription']['subscription_id']
			subscription_name = json_resp['subscription']['name']
			starts_at = json_resp['subscription']['current_term_starts_at']
			ends_at = json_resp['subscription']['current_term_ends_at']
			next_billing_at = json_resp['subscription']['next_billing_at']
			customer_id = json_resp['subscription']['customer']['customer_id']

			user_sites_plan = userSubscriptionPlan(cust_id=user_id, subscription_plan_id=subscription_plan_id, zoho_customer_id=str(customer_id), zoho_subscription_id=str(subscription_id), zoho_subscription_name=str(subscription_name), next_billing=str(next_billing_at), start_date=starts_at, is_active=1, plan_validity='lifetime')
			user_sites_plan.save()

			return "Customer subscribed"
		else:
			return json_resp['message']
	except Exception as e:
		return str(e)

# Cancel any active/existing zoho subscription 
def cancelZohoSubscription(zoho_subscription_id):
	try:
		zoho_token = zohoAuthToken.objects.get(id=1)
		z_authorization = 'Zoho-oauthtoken ' + str(zoho_token.access_token)

		url = "https://subscriptions.zoho.com/api/v1/subscriptions/"+str(zoho_subscription_id)+"/cancel?cancel_at_end=false"
		headers = {
		'X-com-zoho-subscriptions-organizationid': Zoho_Subscriptions_OrgID,
		'Authorization': z_authorization,
		'Content-Type': 'application/json'
		}
		response = requests.request("POST", url, headers=headers, data={})
		json_resp = response.json()
		return json_resp
	except Exception as err:
		return str(err)

# Update user's Zoho subscription
def updateZohoSubscription(zoho_cust_id, planName, description, planPrice, start_date):
	try:		
		zoho_token = zohoAuthToken.objects.get(id=1)
		z_authorization = 'Zoho-oauthtoken ' + str(zoho_token.access_token)

		payload="{\n\t\"customer_id\": \""+zoho_cust_id+"\",\n\t\"plan\": {\n\t\t\"plan_code\": \""+planName+"\",\n\t\t\"plan_description\": \""+description+"\",\n\t\t\"quantity\": \"1\",\n\t\t\"trial_days\": 0,\n\t\t\"setup_fee\": \"0.00\"\n\t},\t\n\t\"starts_at\": \""+start_date+"\",\n\t\"payment_terms\": 0,\n\t\"payment_terms_label\": \"Due on Receipt\",\n\t\"reference_id\": \""+planName+"\",\n\t\"auto_collect\": false\n}"

		headers = {
		'X-com-zoho-subscriptions-organizationid': Zoho_Subscriptions_OrgID,
		'Authorization': z_authorization,
		'Content-Type': 'application/json'
		}
		response = requests.request("POST", Zoho_Subscription_Url, headers=headers, data=payload)
		json_resp = response.json()
		return json_resp
	except Exception as e:
		return str(e)
 
# Zoho Desk - Search Articles
def zohoDeskSearchArticles(result_limit, wild_search):
	try:
		zoho_token = zohoAuthToken.objects.get(id=1)
		z_authorization = 'Zoho-oauthtoken ' + str(zoho_token.access_token)
		
		url = "https://desk.zoho.com/api/v1/articles/search?limit="+result_limit+"&_all="+str(wild_search)+"*"
		headers = {
		'orgId': Zoho_Desk_OrgID,
		'Authorization': z_authorization,
		'Content-Type': 'application/json'
		}

		response = requests.request("GET", url, headers=headers)
		try:
			json_resp = response.json()
			return json_resp
		except Exception as e:
			return { "message": "No result found. "+str(e) }
	except Exception as err:
		return { "message":str(err) }


# Add user to Zoho Campaign Beta User list
def addToZohoCampaign(firstName, lastName, email):
	try:		
		zoho_token = zohoAuthToken.objects.get(id=1)
		z_authorization = 'Zoho-oauthtoken ' + str(zoho_token.access_token)

		headers = {
		'Authorization': z_authorization,
		'Content-Type': 'application/json'
		}
		
		campaign_url = "https://campaigns.zoho.com/api/json/listsubscribe?scope=CampaignsAPI&version=1&resfmt=JSON&listkey=3zc686ab4cf3324883efe67c4baae87744fd4e7b6d52992ebb11110537a4dfdbf0&contactinfo={First Name:"+firstName+",Last Name:"+lastName+",Contact Email:"+email+"}"
		logError(str(campaign_url))
		
		response = requests.request("POST", campaign_url, headers=headers)
		json_resp = response.json()
		return json_resp
	except Exception as e:
		return str(e)

##################################################################################################################################

# Signup function
@csrf_exempt
def createUserAccount(request):
	try:
		final_response = {}
		if request.method == "POST":
			post_data = json.loads(request.body)
			firstName = str(post_data['first_name'])
			lastName = str(post_data['last_name'])
			email = str(post_data['email'])
			password = str(post_data['password'])
			security_code = str(post_data['security_code'])

			#check user if already exists
			try:
				user_data = custMaster.objects.get(email=email)
				email = user_data.email
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = "User already exists"
				return HttpResponse(json.dumps(final_response))
			except custMaster.DoesNotExist:
				try:
					try:
						check_beta = betaTesters.objects.get(email=email, security_code=security_code)	
					except betaTesters.DoesNotExist:	
						final_response['status'] = status.HTTP_400_BAD_REQUEST	
						final_response['message'] = "User cannot register"
						return HttpResponse(json.dumps(final_response))
					
					# create user object
					create_user = User.objects.create_user(email, email, password)
					create_user.first_name = firstName
					create_user.last_name = lastName
					create_user.save()

					# entry in cust_master table
					create_user_profile = custMaster(cust_id=create_user.id, first_name=firstName, last_name=lastName, email=email, display_name=firstName)
					create_user_profile.save()

					# Add customer to ZOHO subscription
					zoho_msg = ''
					try:
						add_zoho_subscription = zohoSubscription(create_user.id, firstName, lastName, email)
						if "You are not authorized to perform this operation" in add_zoho_subscription:
							get_new_token = RefreshZohoToken()
							add_zoho_subscription = zohoSubscription(create_user.id, firstName, lastName, email)
						else:
							zoho_msg = add_zoho_subscription
					except Exception as e:
						zoho_msg = str(e)
					
					try:
						add_to_mail_list = addToZohoCampaign(firstName, lastName, email)
						logError(str(add_to_mail_list))
					except Exception as err:
						logError(str(err))

					final_response['status'] = status.HTTP_200_OK	
					final_response['message'] = 'User successfully created.'
					final_response['details'] = zoho_msg
				except Exception as e:
					final_response['status'] = status.HTTP_400_BAD_REQUEST	
					final_response['message'] = 'Error in saving user info.'
		else:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request on this url'

	except Exception as e:
		final_response['status'] = status.HTTP_500_INTERNAL_SERVER_ERROR	
		final_response['message'] = str(e)
	
	return HttpResponse(json.dumps(final_response))

# User logout
class Logout(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request):
		final_response = {}
		url = str(settings.TOKEN_URL)+'/o/revoke_token/'

		try:
			token = str(request.META['Authorization']).split("Bearer ")[1]
		except Exception:
			token = str(request.headers.get('Authorization')).split("Bearer ")[1]
		
		cleaned_data = {}
		cleaned_data['token'] = token
		cleaned_data['client_id'] = api_client_id
		cleaned_data['client_secret'] = api_client_secret
		req = requests.post(url, data=cleaned_data)
		try:
			req_data = req.text()
		except Exception:
			req_data = req.text
		
		if "Invalid credentials given" in str(req_data):
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['messageType'] = token		
			final_response['message'] = "Invalid token"
		else:
			final_response['status'] = status.HTTP_200_OK	
			final_response['messageType'] = token		
			final_response['message'] = str(req_data) + str(req)
		
		return Response(final_response)


class Index(APIView):

	permission_classes = [TokenHasReadWriteScope]

	def get(self, request, format=None):
		"""
		Return a list of all users.
		
		"""
		
		final_response={}
		allInfo = [] 
		
		allInfo.append(data)
		final_response['data'] = allInfo	
		final_response['messageType'] = "success"		
		final_response['status'] = 200	
		final_response['message'] = "success"
		return Response(final_response)


# API Functions for dashboard
class DashboardAPI(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request):
		try:
			final_response={}
			custID = request.user.id	
			
			plan_id = 0
			export_credits = 0
			total_sites = 0
			end_date = ""

			# website types
			website_types = ssWebsiteType.objects.filter(is_active=1)

			# list of user 
			user_sites = []
			user_sites_list = userSites.objects.filter(cust_id=custID, is_active=1)
			if len(user_sites_list) > 0:
				for sites in user_sites_list:
					site_array = {}
					site_array['site_id'] = sites.id
					site_array['site_name'] = sites.site_name
					site_array['is_active'] = sites.is_active
					site_array['is_domain_connected'] = sites.is_domain_connected
					site_array['is_published'] = sites.is_published
					site_array['template_id'] = sites.template_id
					site_array['content_path'] = sites.json_path
					site_array['created_on'] = str(sites.createdOn.date())
					for web_types in website_types:
						if web_types.id == sites.site_website_type_id:
							site_array['website_type'] = web_types.site_name
					if sites.is_domain_connected == 1:
						try:
							get_general_settings = userGeneralSettings.objects.get(cust_id=custID, user_site_id=sites.id)
							site_array['custom_domain'] = get_general_settings.custom_domain
						except userGeneralSettings.DoesNotExist:
							site_array['custom_domain'] = ""
					else:
						site_array['custom_domain'] = ""

					user_sites.append(site_array)

			# latest offer
			ss_latest_offer = ssLatestOffers.objects.filter(isActive=1)
			latest_offer = {}
			for offer in ss_latest_offer:
				latest_offer['title'] = offer.title
				latest_offer['description'] = offer.description
				latest_offer['short_description'] = offer.shortDescription

			# user account plan and subscription
			active_user_plan = userSubscriptionPlan.objects.get(cust_id=custID, is_active=1)
			plan_id = active_user_plan.subscription_plan_id
			#end_date = 	str(active_user_plan.end_date.date())	
			
			#get plan details
			ss_plan = ssSubscriptionPlans.objects.filter(id=plan_id, is_active=1)
			current_plan = {}
			current_plan['billing_period'] = active_user_plan.next_billing
			current_plan['expires_on'] = active_user_plan.end_date
			for main_plan in ss_plan:
				#current_plan['validity'] = str(main_plan.validity)
				current_plan['validity'] = str(active_user_plan.plan_validity)
				current_plan['description'] = main_plan.description
				if current_plan['validity'] == "lifetime":
					current_plan['expires_on'] = "Never"
				
				if current_plan['validity'] == "monthly":
					current_plan['price'] = main_plan.price_monthly
				else:
					current_plan['price'] = main_plan.price_yearly		




			ss_plan_details = ssSubscriptionPlansDetails.objects.filter(ss_subscription_plans_id=plan_id, is_active=1)
			for plan_details in ss_plan_details:
				current_plan['name'] = plan_details.name
				current_plan['features'] = plan_details.features

				export_credits = plan_details.total_export_credits
				total_sites = plan_details.total_sites
			
			# upgrade plan options
			#all_plans = ssSubscriptionPlans.objects.filter(isActive=1)
			upgrade_plan = []

			# future updates and releases
			future_updates = ssRoadmapReleases.objects.filter(isActive=1)
			upcoming_releases = []
			for releases in future_updates:
				releases_array = {}
				releases_array['title'] = releases.title
				releases_array['description'] = releases.description
				releases_array['update_type'] = releases.updateType
				releases_array['release_date'] = str(releases.releaseDate.date())
				upcoming_releases.append(releases_array)
			total_websites = len(user_sites)

			#user export credits
			user_exports = userExports.objects.filter(cust_id=custID)
			total_exports = len(user_exports)

			final_response['data'] = {"user_sites": user_sites, "latest_offer": latest_offer, "active_user_plan": current_plan, "upgrade_plan": upgrade_plan, "future_updates":upcoming_releases, "total_user_sites":total_websites, "total_user_exports":total_exports, "export_credits":export_credits, "total_sites":total_sites}	
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "success"
			
		except Exception as e:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = str(e)
		return Response(final_response)


# API function for user profile
class UserProfile(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request):
		try:
			final_response={}

			# list of user sites
			custID = request.user.id
			try:
				user_data = {}
				user_info = custMaster.objects.get(cust_id=custID)
				user_data['first_name'] = user_info.first_name
				user_data['last_name'] = user_info.last_name
				user_data['email'] = user_info.email
				user_data['display_name'] = user_info.display_name
				user_data['phone'] = user_info.phone
				user_data['bio'] = user_info.bio
				user_data['last_updated'] = str(user_info.updatedOn.date())
				try:
					user_data['profile_picture'] = user_info.profile_picture.url
				except Exception:
					user_data['profile_picture'] = ""

				#get user sites
				user_sites = []
				user_sites_list = userSites.objects.filter(cust_id=custID, is_active=1)
				if len(user_sites_list) > 0:
					for sites in user_sites_list:
						site_array = {}
						site_array['site_id'] = sites.id
						site_array['site_name'] = sites.site_name
						user_sites.append(site_array)

					#get contributors
					contributors_list = []
					all_contributors = userSiteContributors.objects.filter(cust_id=custID).extra(
						select={'contributor_id':'user_site_contributors.id', 'site_id':'user_site_contributors.user_site_id', 'role':'contributor_role_permissions.role', 'added_on':'DATE(user_site_contributors.createdOn)'},
						tables=['contributor_role_permissions'],
						where=['user_site_contributors.role_id=contributor_role_permissions.id']
					).values('contributor_id', 'site_id', 'name', 'email', 'role', 'added_on')
					
				
				final_response['user_profile'] = user_data	
				final_response['user_sites'] = user_sites	
				final_response['contributors'] = all_contributors	
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "success"
			except Exception as err:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'Bad Request -'+str(err)	
		except Exception as e:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = str(e)         
		return Response(final_response)
	
	def post(self, request):
		try:
			final_response={}

			custID = request.user.id
			
			first_name = request.POST['first_name']	
			last_name = request.POST['last_name']
			phone = request.POST['phone']
			display_name = request.POST['display_name']
			bio = request.POST['bio']
			try:
				profile_picture = request.FILES['profile_picture']
			except:
				try:
					profile_picture = request.POST['profile_picture']
				except:
					profile_picture = ''

			
			user_info = custMaster.objects.get(cust_id=custID)
			user_info.first_name = str(first_name)
			user_info.last_name = str(last_name)
			user_info.phone = str(phone)
			user_info.display_name = str(display_name)
			user_info.bio = str(bio)
			user_info.updatedOn = datetime.datetime.now()

			if profile_picture == '':
				user_info.profile_picture = "default-profile.png"
			else:
				if user_info.profile_picture.url == profile_picture:
					pass
				else:
					user_info.profile_picture = profile_picture

			user_info.save()
			
			#update auth_user table
			auth_user = User.objects.get(id=custID)
			auth_user.first_name = str(first_name)
			auth_user.last_name = str(last_name)
			auth_user.save()

			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "User Profile updated"
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'User not found!'

		return Response(final_response)


# API function for user notification settings
class UserNotificationSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request):
		try:
			final_response={}

			# list of user sites
			custID = request.user.id
			user_notifications = userNotificationSettings.objects.filter(cust_id=custID)
			
			enabled_settings = []
			for notify in user_notifications:
				n_id = notify.notifications_id
				n_setting = notify.setting
				if n_setting == 1:
					enabled_settings.append(n_id)
				
			
			# all notifications
			all_notifications = notifications.objects.filter(is_active=1)

			enabled_notifications = []
			for notfications in all_notifications:
				if notfications.id in enabled_settings:
					enabled_notifications.append({"id": notfications.id, "name":notfications.name, "value": 1})
				else:
					enabled_notifications.append({"id": notfications.id, "name":notfications.name, "value": 0})

			final_response['user_notifications'] = enabled_notifications	
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "success"
			
		except Exception as e:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = str(e)
		return Response(final_response)

	def post(self, request):
		try:
			final_response={}

			# list of user sites
			post_data = request.data
			custID = request.user.id
			notification_settings = post_data["user_notifications"]
			for settings in notification_settings:
				try:
					user_notify = userNotificationSettings.objects.get(notifications_id=settings['id'], cust_id=custID)
					user_notify.setting = settings['value']
					user_notify.updatedOn = datetime.datetime.now()
					user_notify.save()
				except userNotificationSettings.DoesNotExist:			
					user_notify = userNotificationSettings(cust_id=custID, notifications_id=settings['id'], setting=settings['value'])
					user_notify.save()

			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Notifications settings updated"
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Settings not found!' + str(err)		

		return Response(final_response)


# API function for change user password
class ChangePassword(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		try:
			final_response={}

			# list of user sites
			post_data = request.data
			custID = request.user.id
			current_password = post_data["current_password"]
			new_password = post_data["new_password"]
			try:
				get_user = User.objects.get(id=custID)
			except Exception as err:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'User not found! ' + str(err)	
				return Response(final_response)
	
			existing_password = make_password(current_password)
			if get_user.check_password(current_password) == True:
				get_user.set_password(new_password)
				get_user.save()
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "User password updated"
			else:
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "Invalid password"
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = str(err)		

		return Response(final_response)


# API function for user site general settings
class SiteGeneralSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		try:
			final_response={}
			post_data = request.POST
			custID = request.user.id
			site_id = post_data["site_id"]
			action = post_data["action"]
			user_site = userSites.objects.get(id=site_id,cust_id=custID)
			get_general_settings = userGeneralSettings.objects.get(cust_id=custID, user_site_id=site_id)
			if str(action) == 'fetch':
				try:
					general_settings = {}
					general_settings['site_id'] = user_site.id
					general_settings['created_on'] = user_site.createdOn
					general_settings['site_name'] = get_general_settings.project_name
					general_settings['favicon'] = str(get_general_settings.favicon.url)
					general_settings['branding'] = get_general_settings.siteseed_branding
					general_settings['sub_domain'] = get_general_settings.sub_domain
					general_settings['custom_domain'] = get_general_settings.custom_domain

					final_response['general_settings'] = general_settings	
					final_response['status'] = status.HTTP_200_OK	
					final_response['message'] = "success"
				except Exception as err:
					final_response['status'] = status.HTTP_400_BAD_REQUEST	
					final_response['message'] = "Error in getting user sites. "+str(err)
			
			elif str(action) == 'save':
				siteName = post_data['site_name']
				subDomain = post_data['sub_domain']
				branding = post_data['branding']
				customDomain = post_data['custom_domain']
				try:
					fav_icon = request.FILES['favicon']
				except:
					try:
						fav_icon = post_data['favicon']
					except Exception:
						fav_icon = ''
				user_site.site_name = siteName
				user_site.updatedOn = datetime.datetime.now()
				user_site.save()
				get_general_settings.project_name = siteName
				get_general_settings.siteseed_branding = branding 
				get_general_settings.sub_domain = subDomain
				get_general_settings.custom_domain = customDomain
				get_general_settings.updatedOn = datetime.datetime.now()
				if fav_icon == '':
					get_general_settings.favicon = "default-favicon.png"
				else:
					if get_general_settings.favicon.url == fav_icon:
						pass
					else:
						get_general_settings.favicon = fav_icon		
				
				get_general_settings.save()
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "General settings updated."
			else:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'Invalid operation'	
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Settings not found'	

		return Response(final_response)	


# API function for user site seo settings
class SiteSEOSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		try:
			final_response={}
			custID = request.POST['custID']
			siteID = request.POST['site_id']
			action = request.POST['action']
			if str(action) == 'fetch':
				get_seo_settings = userSeoSettings.objects.get(cust_id=custID, user_site_id=siteID)
				final_response['data'] = {"seo_settings": get_seo_settings}		
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "success"
			else:
				robots_txt = request.POST['robots_txt']
				sitemap = request.POST['sitemap']
				sitemap_xml = request.POST['sitemap_xml']
				
				get_seo_settings = userSeoSettings.objects.get(cust_id=custID, user_site_id=siteID)
				get_seo_settings.favicon = fav_icon
				get_seo_settings.siteseed_branding = displayBadge
				get_seo_settings.sub_domain = sub_domain
				get_seo_settings.save()
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Settings not found'	

		return Response(final_response)	


# API function for user site forms settings
class GetSiteFormSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request, siteID):
		try:
			final_response={}
			post_data = request.data
			custID = request.user.id
			#siteID = post_data['site_id']
			try:
				get_form_settings = userFormsSettings.objects.get(cust_id=custID, user_site_id=siteID)
				form_settings = {}
				form_settings['form_id'] = get_form_settings.id
				form_settings['form_name'] = get_form_settings.form_name
				form_settings['submition_to_address'] = get_form_settings.submition_to_address
				form_settings['subject_line'] = get_form_settings.subject_line
				form_settings['reply_address'] = get_form_settings.reply_address
				form_settings['form_submission_count'] = get_form_settings.form_submission_count

				final_response['form_settings'] = form_settings		
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "success"
			except userFormsSettings.DoesNotExist:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = "Form settings not found. Invalid parameters."	
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = "Bad request. "+str(err)	

		return Response(final_response)		

class SiteFormSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]	
	def post(self, request):
		try:
			final_response={}
			post_data = request.data
			custID = request.user.id
			siteID = post_data['site_id']
			#form_id = post_data['form_id']
			form_name = post_data['form_name']
			submition_to_address = post_data['submition_to_address']
			subject_line = post_data['subject_line']
			reply_address = post_data['reply_address']
			form_submission_count = post_data['form_submission_count']
			try:
				get_form_settings = userFormsSettings.objects.get(cust_id=custID, user_site_id=siteID)
				get_form_settings.form_name = form_name
				get_form_settings.submition_to_address = submition_to_address
				get_form_settings.subject_line = subject_line
				get_form_settings.reply_address = reply_address
				get_form_settings.form_submission_count = form_submission_count
				get_form_settings.updatedOn = datetime.datetime.now()
				get_form_settings.save()
			except userFormsSettings.DoesNotExist:			
				font_setting = userFormsSettings(cust_id=custID, user_site_id=siteID, form_name=form_name, submition_to_address=submition_to_address, subject_line=subject_line, reply_address=reply_address, form_submission_count=form_submission_count)
				font_setting.save()
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'Form settings updated.'
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Settings not found'	

		return Response(final_response)	


# API function for user site fonts settings
class GetSiteFontsSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request, siteID):
		try:
			final_response={}
			custID = request.user.id
			try:
				get_font_settings = userFontsSettings.objects.get(cust_id=custID, user_site_id=siteID)
				font_settings = {}
				font_settings['font_id'] = get_font_settings.id
				font_settings['adobe_fonts_key'] = get_font_settings.adobe_fonts_key

				final_response['font_settings'] = font_settings		
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "success"
			except userFontsSettings.DoesNotExist:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = "Font settings not found."	
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = "Bad request. "+str(err)	

		return Response(final_response)

class SiteFontsSettings(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		try:
			final_response={}
			post_data = request.data
			custID = request.user.id
			siteID = post_data['site_id']
			#font_id = post_data['font_id']
			#try:
			#	custom_font = request.FILES['custom_fonts']
			#except:
			#	custom_font = ''

			adobe_fonts_key = post_data['adobe_fonts_key']
			try:
				get_fonts_settings = userFontsSettings.objects.get(cust_id=custID, user_site_id=siteID)
				#get_fonts_settings.custom_font = custom_font
				get_fonts_settings.adobe_fonts_key = adobe_fonts_key
				get_fonts_settings.updatedOn = datetime.datetime.now()
				get_fonts_settings.save()
			except userFontsSettings.DoesNotExist:			
				font_setting = userFontsSettings(cust_id=custID, user_site_id=siteID, custom_fonts="", adobe_fonts_key=adobe_fonts_key)
				font_setting.save()
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Adobe Api key updated."
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)	

		return Response(final_response)	


# API function for user site backups settings
class SiteBackups(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		try:
			final_response={}
			custID = request.POST['custID']
			siteID = request.POST['site_id']
			action = request.POST['action']
			if str(action) == 'fetch':
				get_backups = userBackupSettings.objects.get(cust_id=custID, user_site_id=siteID)
				final_response['data'] = {"backups": get_backups}		
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "success"
			else:
				backup_path = request.POST['backup_path']
				backup_date = request.POST['backup_date']
				
				get_backups = userBackupSettings.objects.get(cust_id=custID, user_site_id=siteID)
				get_backups.backup_path = backup_path
				get_backups.backup_date = backup_date
				get_backups.save()

		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Settings not found'	

		return Response(final_response)	


# API function for inviting contributors to site
class SiteContributors(APIView):
	permission_classes = [TokenHasReadWriteScope]
	# for adding contributor (invite)
	def post(self, request):
		final_response={}
		try:
			post_data = request.POST
			custID = request.user.id
			site_id = post_data["site_id"]
			name = post_data["name"]
			email = post_data["email"]
			role = post_data["role"]
			
			check_contributor = userSiteContributors.objects.filter(email=email)
			if len(check_contributor) > 0:
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = "Contributor already added to site."
				return Response(final_response)				

			user_info = custMaster.objects.get(cust_id=custID)
			sender_name = f"{user_info.first_name} {user_info.last_name}"

			add_contributor = userSiteContributors(cust_id=custID, user_site_id=site_id, name=name, email=email, role_id=role)
			add_contributor.save()

			get_role = contributorRolePermission.objects.get(id=int(role))
			if get_role.role == 'Preview Only':
				contributor_role = "preview"
			elif get_role.role == 'Editor':
				contributor_role = "edit"
			else:
				contributor_role = "edit and preview"

			# send email to contributor
			sg = sendgrid.SendGridAPIClient(api_key=str(settings.SENDGRID_API_KEY)) 
			personalization = Personalization() 
			personalization.add_to(Email(str(email))) 
			personalization.dynamic_template_data={"to_name":str(name), "role":contributor_role, "sender_name":sender_name, "signup_link":"http://dev.siteseed.io/#/create-account"}
			mail = Mail() 
			mail.from_email = Email(str(settings.SENDGRID_FROM_EMAIL)) 
			mail.subject = "SiteSeed Invitation" 
			mail.add_personalization(personalization) 
			mail.template_id = "d-8376a154c1134bf19e628dd4a34309ac" 
			try:
				response = sg.client.mail.send.post(request_body=mail.get())
				resposne_array = response.headers
			except exceptions.BadRequestsError as e:
				# ~ return HttpResponse(str(e.body))
				resposne_array = str(e.body)

			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Contributor added to site."
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = "Error adding contributor "+str(err)

		return Response(final_response)	
	
	# update contributor role
	def put(self, request):
		try:
			final_response={}
			post_data = request.POST
			custID = request.user.id
			site_id = post_data["site_id"]
			contributor_id = post_data["contributor_id"]
			role = post_data["role"]
			update_contrib_role = userSiteContributors.objects.get(id=contributor_id, user_site_id=site_id)
			update_contrib_role.role_id = role
			update_contrib_role.updatedOn = datetime.datetime.now()
			update_contrib_role.save()
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Contributor role updated."
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = "Error updating contributor "+str(err)	

		return Response(final_response)
	
	# delere contributor from site
	def delete(self, request):
		try:
			final_response={}
			post_data = request.POST
			custID = request.user.id
			site_id = post_data["site_id"]
			contributor_id = post_data["contributor_id"]
			delete_contrib = userSiteContributors.objects.get(id=contributor_id, user_site_id=site_id)
			delete_contrib.delete()
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Contributor removed."
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = str(err)	

		return Response(final_response)					


# Dashboard search bar function
class SearchBarFilter(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		query = None
		#results = []
		final_response={}
		try:
			query = request.POST['query']
			result_limit='5'
			get_desk_articles = zohoDeskSearchArticles(result_limit, str(query))
			try:
				check_response_msg = get_desk_articles['message']
			except:
				check_response_msg = ""
			if "You are not authorized to perform this operation" in check_response_msg or "The OAuth Token you provided is invalid." in check_response_msg:
				get_new_token = RefreshZohoToken()
				get_desk_articles = zohoDeskSearchArticles(result_limit, str(query))
			

			# search_query = ssFAQs.objects.filter(Q(title__icontains=query) | Q(description__icontains=query) | Q(short_description__icontains=query) )
			# for records in search_query:
			# 	result_array = {}
			# 	result_array['title'] = records.title
			# 	result_array['description'] = records.description
			# 	result_array['short_description'] = records.short_description
			# 	result_array['url'] = "http://dev.siteseed.io/#/dashboard"
			# 	results.append(result_array)
			
			# if len(results) > 0:
			# 	final_response['search_results'] = results
			# 	if len(results) > 1:
			# 		final_response['message'] = str(len(results))+" results found."
			# 	else:
			# 		final_response['message'] = str(len(results))+" result found."
			# else:
			# 	final_response['message'] = "No result found!"
			article_list = []
			try:
				for articles in get_desk_articles['data']:
					data_array = {}
					data_array['title'] = articles['title']
					data_array['summary'] = articles['summary']
					data_array['portalUrl'] = articles['portalUrl']
					article_list.append(data_array)
			except Exception as err:
				article_list=[]

			final_response['search_result'] = article_list
			final_response['status'] = status.HTTP_200_OK	
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)	

		return Response(final_response)					
 

# Customer's billing information api
class BillingInformation(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request):
		final_response={}
		try:
			custID = request.user.id
			# user existing cards
			existing_cards = userPaymentMethod.objects.filter(cust_id=custID, is_active=1)
			existing_billing_info = userBillingAddress.objects.filter(cust_id=custID)
			user_cards = []
			if len(existing_cards) > 0:
				for cards in existing_cards:
					card_details = {}
					card_details['id'] = cards.id
					card_details['last4'] = cards.last4
					card_details['exp_month'] = cards.exp_month
					card_details['exp_year'] = cards.exp_year
					card_details['brand'] = cards.brand
					card_details['is_default'] = cards.is_default
					card_details['billing_info'] = {}
					for bill_info in existing_billing_info:
						if bill_info.payment_method_id == cards.id:
							info_array = {}
							info_array['address_line_1'] = bill_info.address_line_1
							info_array['address_line_2'] = bill_info.address_line_2
							info_array['city'] = bill_info.city
							info_array['state'] = bill_info.state
							info_array['zipcode'] = bill_info.zipcode
							info_array['country'] = bill_info.country
							info_array['phone'] = bill_info.phone
							card_details['billing_info'] = info_array
					
					user_cards.append(card_details)

			# getting payment history
			all_payments = paymentHistory.objects.filter(cust_id=custID).extra(
				select={'orderID':'payment_history.id', 'billing_date':'DATE(payment_history.createdOn)', 'card': 'user_payment_method.last4', 'brand': 'user_payment_method.brand'},
				tables=['user_payment_method'],
				where=['payment_history.payment_method_id=user_payment_method.id']
			).values('orderID', 'total', 'subtotal', 'tax', 'description', 'card', 'brand', 'billing_date')	
			
			# get user details
			user_data = {}
			user_info = custMaster.objects.get(cust_id=custID)
			user_data['first_name'] = user_info.first_name
			user_data['last_name'] = user_info.last_name
			user_data['email'] = user_info.email
			user_data['phone'] = user_info.phone
			
			final_response['data'] = {"payment_methods":user_cards, "billing_history": all_payments, "user_details":user_data}	
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "success"

		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)	

		return Response(final_response)	


class UserSubscription(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def get(self, request):
		final_response={}
		try:
			custID = request.user.id

			# user account plan and subscription
			active_user_plan = userSubscriptionPlan.objects.get(cust_id=custID, is_active=1)
			plan_id = active_user_plan.subscription_plan_id
			try:
				start_date = datetime.datetime.strptime(str(active_user_plan.start_date), "%Y-%m-%d").strftime("%B %d, %Y")	
			except Exception as e:
				start_date = str(e)
			try:	
				end_date = 	datetime.datetime.strptime(str(active_user_plan.end_date), "%Y-%m-%d").strftime("%B %d, %Y")
			except Exception:
				end_date = ""
			
			card = ""
			brand = ""
			payemnt_detail = paymentHistory.objects.filter(cust_id=custID, subscription_id=active_user_plan.zoho_subscription_id).extra(
				select={'card': 'user_payment_method.last4', 'brand': 'user_payment_method.brand'},
				tables=['user_payment_method'],
				where=['payment_history.payment_method_id=user_payment_method.id']
			).values('card', 'brand')	
			for p_details in payemnt_detail:
				card = p_details['card']
				brand = p_details['brand']

			#get plan details
			ss_plan = ssSubscriptionPlans.objects.filter(is_active=1)
			ss_plan_details = ssSubscriptionPlansDetails.objects.filter(is_active=1)
			#ss_plan = ssSubscriptionPlans.objects.filter(id=plan_id, is_active=1)
			current_plan = {}
			upgrade_plans = []
			for main_plan in ss_plan:
				other_plan = {}
				if main_plan.id == plan_id:
					for plan_details in ss_plan_details:
						if plan_details.ss_subscription_plans_id == plan_id:
							current_plan['plan_id'] = main_plan.id
							current_plan['name'] = plan_details.name
							current_plan['description'] = main_plan.description
							current_plan['validity'] = str(active_user_plan.plan_validity)
							current_plan['price'] = main_plan.price_monthly	
							current_plan['price_monthly'] = main_plan.price_monthly	
							current_plan['price_yearly'] = main_plan.price_yearly	
							current_plan['billing_period_start'] = start_date	
							current_plan['end_date'] = end_date	
							current_plan['card'] = card	
							current_plan['brand'] = brand	
				else:
					for plan_details in ss_plan_details:
						if plan_details.ss_subscription_plans_id == main_plan.id:
							other_plan['plan_id'] = main_plan.id
							other_plan['name'] = plan_details.name
							other_plan['description'] = main_plan.description
							other_plan['features'] = plan_details.features
							other_plan['validity'] = str(active_user_plan.plan_validity)
							other_plan['price'] = main_plan.price_monthly
							other_plan['price_monthly'] = main_plan.price_monthly
							other_plan['price_yearly'] = main_plan.price_yearly
							upgrade_plans.append(other_plan)

			final_response['data'] = {"active_user_plan": current_plan, "other_plans": upgrade_plans}	
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "success"

		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)	

		return Response(final_response)	


# API for Adding card (payment method) to customer's account
class AddPaymemtMethod(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			address_line_1 =  str(request.POST['address_line_1'])
			address_line_2 =  str(request.POST['address_line_2'])
			city =  str(request.POST['city'])
			state =  str(request.POST['state'])
			zipcode =  str(request.POST['zipcode'])
			country =  str(request.POST['country'])
			phone =  str(request.POST['phone'])

			#card_no =  str(request.POST['card_no'])
			#exp_month = int(request.POST['exp_month'])
			#exp_year = int(request.POST['exp_year'])
			#cvc = str(request.POST['cvc'])
			source_token = str(request.POST['source_token'])

			try:
				stripe_customer = ssStripeCustomers.objects.get(cust_id=custID)
				stripe_cust_id = stripe_customer.stripe_id
			except ssStripeCustomers.DoesNotExist:
				
				
				# create customer on Stripe
				user_data = custMaster.objects.get(cust_id=custID)
				email = user_data.email
				cust_name = user_data.first_name + " " + user_data.last_name
				#phone = user_data.phone
				create_customer = stripe.Customer.create(
					email = str(email),
					name = str(cust_name),
					description="Siteseed Customer",
				
				)
				stripe_cust_id = create_customer.id
				# save customer data in ssStripeCustomers tabel 
				saveStripe = ssStripeCustomers(cust_id=custID,stripe_id=stripe_cust_id)
				saveStripe.save()
				
			# validate card and get token
			# create_card_token = stripe.Token.create(
			# 					card={
			# 						"number": card_no,
			# 						"exp_month": exp_month,
			# 						"exp_year": exp_year,
			# 						"cvc": cvc,		
			# 					},
			# 					)
			# source_token = create_card_token.id
			create_card = stripe.Customer.create_source(
				stripe_cust_id,
				source=source_token,
				)
			card_id = create_card.id
			exp_month = create_card.exp_month 	
			exp_year = create_card.exp_year
			last4 = create_card.last4
			brand = create_card.brand 

			# check if user has existing cards
			existing_cards = userPaymentMethod.objects.filter(cust_id=custID, is_default=1)
			if len(existing_cards) > 0:
				isDefault = 0
			else:
				isDefault = 1
			
			add_payment_method = userPaymentMethod(cust_id=custID, card_id=card_id, last4=last4, exp_month=exp_month, exp_year=exp_year, is_default=isDefault, is_active=1)		
			add_payment_method.save()	

			add_billing_info = userBillingAddress(cust_id=custID,payment_method_id=add_payment_method.id, address_line_1=address_line_1, address_line_2=address_line_2, city=city, state=state, zipcode=zipcode, country=country, phone=phone)
			add_billing_info.save()			  
			
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Card added successfully"

		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)	
		return Response(final_response)	


#API for updating / removing user card
class UpdatePaymemtMethod(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			card_id = int(request.POST['card_id'])
			exp_month = int(request.POST['exp_month'])
			exp_year = int(request.POST['exp_year'])
			is_default = int(request.POST['is_default'])
			
			address_line_1 =  str(request.POST['address_line_1'])
			address_line_2 =  str(request.POST['address_line_2'])
			city =  str(request.POST['city'])
			state =  str(request.POST['state'])
			zipcode =  str(request.POST['zipcode'])
			country =  str(request.POST['country'])
			phone =  str(request.POST['phone'])

			stripe_customer = ssStripeCustomers.objects.get(cust_id=custID)
			stripe_cust_id = stripe_customer.stripe_id
			
			# get card details
			get_existing_card = userPaymentMethod.objects.get(id=card_id)
			stripe_card_id = str(get_existing_card.card_id)
			
			#update detials on Stripe source
			update_source = stripe.Customer.modify_source(
				str(stripe_cust_id),
				stripe_card_id,
				exp_month= exp_month,
				exp_year=exp_year,
				address_city=city,
				address_country=country,
				address_line1=address_line_1,
				address_line2=address_line_2,
				address_state=state,
				address_zip=zipcode
			)

			# set default card
			if is_default == 1:
				# update all cards is_default = 0
				existing_cards = userPaymentMethod.objects.filter(cust_id=custID, is_default=1).update(is_default=0)

				# set current card as default
				get_existing_card.is_default = 1		
			
			get_existing_card.exp_month = exp_month	
			get_existing_card.exp_year = exp_year
			get_existing_card.updatedOn = datetime.datetime.now()
			get_existing_card.save()				  

			try:
				update_billing_info = userBillingAddress.objects.get(payment_method_id=card_id, cust_id=custID)
				update_billing_info.address_line_1=address_line_1
				update_billing_info.address_line_2=address_line_2
				update_billing_info.city=city
				update_billing_info.state=state
				update_billing_info.zipcode=zipcode
				update_billing_info.country=country
				update_billing_info.phone=phone
				update_billing_info.updatedOn = datetime.datetime.now()
				update_billing_info.save()
			except userBillingAddress.DoesNotExist:
				add_billing_info = userBillingAddress(cust_id=custID,payment_method_id=card_id, address_line_1=address_line_1, address_line_2=address_line_2, city=city, state=state, zipcode=zipcode, country=country)
				add_billing_info.save()

			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Card details updated"

		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	

	def delete(self, request):
		final_response={}
		try:
			custID = request.user.id
			card_id = int(request.POST['card_id'])

			stripe_customer = ssStripeCustomers.objects.get(cust_id=custID)
			stripe_cust_id = str(stripe_customer.stripe_id)
			
			# get card details
			get_existing_card = userPaymentMethod.objects.get(id=card_id)
			stripe_card_id = str(get_existing_card.card_id)
			
			# delete source from Stripe
			update_source = stripe.Customer.delete_source(
				stripe_cust_id,
				stripe_card_id
			)

			# de-activate the card in DB
			get_existing_card.is_active = 0	
			get_existing_card.save()				  
			 
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "Card removed"

		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	


# Create new user's site
class CreateSite(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		final_response={}	
		try:
			custID = request.user.id
			site_name =  str(request.POST['site_name'])
			# check if site already exists
			get_sites = userSites.objects.filter(cust_id=custID, site_name=site_name, is_active=1)
			if len(get_sites) > 0:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'This site already exists.'
				return Response(final_response)	
			else:
				# create new user site
				create_user_site = userSites(cust_id=custID, site_name=site_name, is_active=1)	
				create_user_site.save()	

				#save general settings
				general_settings = userGeneralSettings(cust_id=custID, user_site_id=create_user_site.id, project_name=site_name)	
				general_settings.save()
				
				final_response['site_info'] = {"site_id":create_user_site.id, "site_name":create_user_site.site_name}			  
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = 'User site created.'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	


# All SiteSeed template showcase
class SiteseedTemplates(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		final_response={}	
		try:
			t_name =  str(request.POST['t_name'])
			thumbnail = request.FILES['thumbnail']
			path =  str(request.POST['path'])
			t_type =  str(request.POST['t_type'])
			price =  str(request.POST['price'])

			# check if site already exists
			add_template = ssTemplates(template_name=t_name, thumbnail=thumbnail, path=path, template_type=t_type, price=price)
			add_template.save()				  
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'Template Added'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)		
	
	def get(self, request):
		final_response={}	
		try:
			custID = request.user.id
			# check if site already exists
			all_template = ssTemplates.objects.filter(is_active=1)
			get_purchased_templates = userPurchasedTemplates.objects.filter(cust_id=custID)
			purchased_templates = []
			if len(get_purchased_templates) > 0:
				for p_tmp in get_purchased_templates:
					purchased_templates.append(int(p_tmp.template_id))
			template_list = []
			for temps in all_template:
				t_array = {}
				t_array['name'] = temps.template_name	
				t_array['thumbnail'] = temps.thumbnail.url	
				t_array['path'] = temps.path	
				t_array['template_type'] = temps.template_type	
				t_array['price'] = temps.price	
				t_array['template_id'] = temps.id	
				if int(temps.id) in purchased_templates:
					t_array['is_purchased'] = "Yes"
				else:
					t_array['is_purchased'] = "No"

				template_list.append(t_array)
			
			final_response['templates'] = template_list
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = "success"
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)	
		return Response(final_response)		


# Purchase template API function
class PurchaseTemplate(APIView):
	permission_classes = [TokenHasReadWriteScope]
	def post(self, request):
		final_response={}	
		try:
			custID = request.user.id
			site_id =  str(request.POST['site_id'])
			template_id =  int(request.POST['template_id'])
			template_name =  str(request.POST['template_name'])
			card_id = str(request.POST['card_id'])
			promo_code =  request.POST['promo_code']
			discount =  decimal.Decimal(request.POST['discount'])
			subtotal =  decimal.Decimal(request.POST['subtotal'])
			total =  decimal.Decimal(request.POST['total'])
			
			paymentDetail = userPaymentMethod.objects.get(cust_id=custID, id=card_id)
			cardID = paymentDetail.card_id
			
			stripeDetail = ssStripeCustomers.objects.get(cust_id=custID)
			stripe_id = stripeDetail.stripe_id
			charge_description = "Template Purchased - " + template_name
			# stripe charge for the selected plan
			createCharge = stripe.Charge.create(
			amount= int(total * 100),
			currency="usd",
			source=str(cardID),
			customer=str(stripe_id),
			description=charge_description,
			)
			try:
				charge_id = createCharge.id
			except Exception as e:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'Error while processing payment'				
				return Response(final_response)	

			# add data in payment history table
			history = paymentHistory(cust_id=custID, payment_method_id=paymentDetail.id, charge_id=charge_id, subtotal=decimal.Decimal(subtotal), total=decimal.Decimal(total),description=charge_description, discount=decimal.Decimal(discount), promo_code=promo_code)	
			history.save()
			
			# add template to site
			user_site = userSites.objects.get(cust_id=custID, id=site_id)
			user_site.template_id = template_id
			user_site.save()

			# save template in purchases 
			save_in_purchases = userPurchasedTemplates(cust_id=custID, template_id=template_id, template_name=template_name)
			save_in_purchases.save()
			
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'Template purchased and added to site.'				  
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	


# Save template id to site if template is free or already purchased
class SaveTemplateToSite(APIView):
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			site_id =  int(request.POST['site_id'])
			template_id =  int(request.POST['template_id'])
			
			# add template to site
			user_site = userSites.objects.get(cust_id=custID, id=site_id)
			user_site.template_id = template_id
			user_site.save()
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'Template added to site.'	
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)


# Save S3 path of json file of user site
class SaveSitePath(APIView):
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			site_id =  int(request.POST['site_id'])
			path =  str(request.POST['path'])
			try:
				get_site = userSites.objects.get(cust_id=custID, id=site_id)
				# Not deleting site in actual but just making it in-active
				get_site.json_path = path
				get_site.save()
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = 'Site path saved'
			except userSites.DoesNotExist:			
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'User site does not exists!'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)


# Delete user site
class DeleteUserSite(APIView):
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			site_id =  int(request.POST['site_id'])
			try:
				get_site = userSites.objects.get(cust_id=custID, id=site_id)
				# Not deleting site in actual but just making it in-active
				get_site.is_active = 0
				get_site.save()
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = 'Site deleted'
			except userSites.DoesNotExist:			
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'User site does not exists!'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)	


# Promo Codes
class PromoCodes(APIView):
	def post(self, request):
		final_response={}
		try:
			try:
				check_code = ssPromoCodes.objects.get(code=code, is_active=1)
				discount = check_code.discount_price 
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = 'success'
				final_response['data'] = {"discount": discount}
			except ssPromoCodes.DoesNotExist:			
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'Invalid promo code'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)	

# Check promo code 	validity	
class CheckPromoCode(APIView):
	def post(self, request):
		final_response={}
		try:
			code =  str(request.POST['code'])
			check_code = ssPromoCodes.objects.get(code=code, is_active=1)
			discount = check_code.discount_price 
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
			final_response['data'] = {"discount": round(discount,2)}
		except ssPromoCodes.DoesNotExist:			
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Invalid promo code'
	
		return Response(final_response)	


# Upgrade/downgrade subscription plan
class ChangeUserPlan(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			subscription_plan_id = request.POST['subscription_plan_id']
			choosed_type = request.POST['plan_type']
			start_date = str(datetime.date.today())
			#end_date = (start_date + datetime.timedelta(days=30))
			is_active = 1
			
			# getting default card
			try:
				paymentDetail = userPaymentMethod.objects.get(cust_id=custID, is_default=1, is_active=1)
				cardID = paymentDetail.card_id
			except Exception:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = "Payment method not found."
				return Response(final_response)					
			
			# getting Stripe Customer ID
			stripeDetail = ssStripeCustomers.objects.get(cust_id=custID)
			stripe_id = stripeDetail.stripe_id
			
			# getting plan price  
			planDetail = ssSubscriptionPlans.objects.get(id=subscription_plan_id)
			if choosed_type == "Monthly" or choosed_type == "monthly":
				planPrice = planDetail.price_monthly
				planName = planDetail.plan_name_monthly
			else:
				planPrice = planDetail.price_yearly
				planName = planDetail.plan_name_yearly

			plan_description = "Plan Purchase : "+planDetail.description
			
			if planPrice > 0.00:
				# stripe charge for the selected plan
				createCharge = stripe.Charge.create(
				amount= int(planPrice * 100),
				currency="usd",
				source=str(cardID),
				customer=str(stripe_id),
				description=plan_description,
				)
				try:
					charge_id = createCharge.id
				except Exception as e:
					final_response['status'] = status.HTTP_400_BAD_REQUEST	
					final_response['message'] = 'Error while processing payment'				
					return Response(final_response)

			zoho_msg = ''
			subscription_id = ''
			try:
				updatePlan = userSubscriptionPlan.objects.get(cust_id=custID)
				zoho_cust_id = str(updatePlan.zoho_customer_id)
				# cancel existing subscription
				cancel_zoho_sub = cancelZohoSubscription(updatePlan.zoho_subscription_id)
				if "You are not authorized to perform this operation" in cancel_zoho_sub['message']:
					get_new_token = RefreshZohoToken()
					cancel_zoho_sub = cancelZohoSubscription(updatePlan.zoho_subscription_id)
				
				updatePlan.is_active = 0
				updatePlan.save()

				update_zoho_subscription = updateZohoSubscription(zoho_cust_id, planName, planDetail.description, planPrice, start_date)
				if "You are not authorized to perform this operation" in update_zoho_subscription['message']:
					get_new_token = RefreshZohoToken()
					update_zoho_subscription = updateZohoSubscription(zoho_cust_id, planName, planDetail.description, planPrice, start_date)
					
				if "Subscription has been created successfully." in update_zoho_subscription['message']:
					# add subscription plan with default plan id ss_free
					subscription_id = update_zoho_subscription['subscription']['subscription_id']
					subscription_name = update_zoho_subscription['subscription']['name']
					starts_at = update_zoho_subscription['subscription']['current_term_starts_at']
					ends_at = update_zoho_subscription['subscription']['current_term_ends_at']
					next_billing_at = update_zoho_subscription['subscription']['next_billing_at']
					customer_id = update_zoho_subscription['subscription']['customer']['customer_id']
										
					updatePlan.subscription_plan_id = subscription_plan_id
					updatePlan.zoho_customer_id=str(customer_id)
					updatePlan.zoho_subscription_id=str(subscription_id)
					updatePlan.zoho_subscription_name = str(subscription_name)
					updatePlan.start_date = starts_at
					updatePlan.is_active = 1
					updatePlan.end_date = ends_at
					updatePlan.next_billing = next_billing_at
					
					if planPrice > 0.00:	
						updatePlan.plan_validity = choosed_type
					else:
						updatePlan.plan_validity = "lifetime"						

					updatePlan.save()
				else:
					zoho_msg = update_zoho_subscription['message']
			except Exception as e:
				zoho_msg = str(e)

			if planPrice > 0.00:
				# add data in payment history table
				history = paymentHistory(cust_id=custID, payment_method_id=paymentDetail.id, charge_id=charge_id, subtotal=decimal.Decimal(planPrice), total=decimal.Decimal(planPrice),description=plan_description, subscription_id=str(subscription_id))	
				history.save()

			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'Plan Changed'
			final_response['details'] = zoho_msg
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)					


# Invoices - Payment history
class BillingHistory(APIView):
	def get(self, request):
		final_response={}
		try:
			custID = request.user.id
			
			# getting payment history
			all_payments = paymentHistory.objects.filter(cust_id=custID).extra(
				select={'orderID':'payment_history.id', 'billing_date':'DATE(payment_history.createdOn)', 'card': 'user_payment_method.last4', 'brand': 'user_payment_method.brand'},
				tables=['user_payment_method'],
				where=['payment_history.payment_method_id=user_payment_method.id']
			).values('orderID', 'subtotal', 'total', 'tax', 'discount', 'description', 'card', 'brand', 'billing_date')
			
			final_response['billing_history'] = all_payments
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		return Response(final_response)	



class UserExports(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			custID = str(request.user.id)
			site_id = str(request.POST['site_id'])
			platform = str(request.POST['platform'])

			record_export = userExports(cust_id=custID, site_name=site_id, platform=platform)	
			record_export.save()
			
			final_response['description'] = "Export record saved"
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
	
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	


import boto3
aws_access_key_id = "AKIAXUYOEXCRX7UNGK4P"
aws_secret_access_key = "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"
# set aws credentials 
s3r = boto3.resource('s3', aws_access_key_id=aws_access_key_id,
	aws_secret_access_key=aws_secret_access_key)
bucket = s3r.Bucket('siteseed-dev')

class saveSiteFiles(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			custID = str(request.user.id)
			site_id = str(request.POST['site_id'])
			s3_folder = str(request.POST['s3_folder_path'])

			local_dir = f"/var/www/UserSites/{custID}/{site_id}/"
			for obj in bucket.objects.filter(Prefix=s3_folder):
				target = obj.key if local_dir is None \
					else os.path.join(local_dir, os.path.relpath(obj.key, s3_folder))
				if not os.path.exists(os.path.dirname(target)):
					os.makedirs(os.path.dirname(target))
				if obj.key[-1] == '/':
					continue
				bucket.download_file(obj.key, target)
			
			try:
				user_stite = userSites.objects.get(id=int(site_id))
				user_stite.is_published = 1
				user_stite.folder_path = local_dir
				user_stite.updatedOn = datetime.datetime.now()
				user_stite.save()
			except Exception as err:
				final_response['other_msg'] = str(err)

			final_response['description'] = "Files downloaded"
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
	
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	



class BetaCodeGenerator(APIView):
	def post(slef, request):
		final_response={}
		try:
			email = str(request.POST['email'])
			
			random_letters = string.ascii_lowercase + string.digits

			random_code = ''.join(random.choice(random_letters) for i in range(10))
			
			try:

				check_beta = betaTesters.objects.get(email=email)	
				final_response['security_code'] = "This user already have a security code."
			except betaTesters.DoesNotExist:
				beta_testers = betaTesters(email=email, security_code=random_code)
				beta_testers.save()
				final_response['security_code'] = random_code

			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	



class roadMap(View):
	def get(self, request):

		base_url = "https://api.loopedin.io/v1"
		productStashApi = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50IjoiNWZkYzUzODY4NWEyM2IwMDJiY2UxNWMwIiwiZW1haWwiOiJncmVnQGJyaWdodC1kZXZlbG9wbWVudC5jb20iLCJuYW1lIjoiR3JlZyBKYWNvYnkiLCJpYXQiOjE2MjA5Njg1OTl9.2EweMDRS3hCdDtzqPYjwlMxhi9jM-JNqzWeNALo0cd8"

		headers = {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + productStashApi
		}

		retrieve_domain_url = base_url + '/roadmaps'
		retrieve_req = requests.request("GET", retrieve_domain_url, headers=headers, data={})
		retrieve_response = retrieve_req.json()
	
		return HttpResponse(json.dumps(retrieve_response), content_type='application/json')


class roadMapCard(View):
	def get(self, request):

		base_url = "https://api.loopedin.io/v1"
		productStashApi = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50IjoiNWZkYzUzODY4NWEyM2IwMDJiY2UxNWMwIiwiZW1haWwiOiJncmVnQGJyaWdodC1kZXZlbG9wbWVudC5jb20iLCJuYW1lIjoiR3JlZyBKYWNvYnkiLCJpYXQiOjE2MjA5Njg1OTl9.2EweMDRS3hCdDtzqPYjwlMxhi9jM-JNqzWeNALo0cd8"

		headers = {
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + productStashApi
		}

		retrieve_domain_url = base_url + '/roadmap-cards'
		retrieve_req = requests.request("GET", retrieve_domain_url, headers=headers, data={})
		retrieve_response = retrieve_req.json()
	
		return HttpResponse(json.dumps(retrieve_response), content_type='application/json')



class test(View):
	#permission_classes = [TokenHasReadWriteScope]
	
	def get(self, request):

		base_url = "https://api.ote-godaddy.com"

		payload={}
		headers = {
			'accept': 'application/json',
			"X-Shopper-Id": X_Shopper_ID,
			'Content-Type': 'application/json',
			'Authorization': f'sso-key {Reseller_CID}:{Reseller_Secret}'
			}
		domain = "lds.school"
		retrieve_domain_url = GD_BASE_URL+"/v1/domains/"+domain
		retrieve_req = requests.request("GET", retrieve_domain_url, headers=headers, data={})
		retrieve_response = retrieve_req.json()
		
					

		return HttpResponse(str(retrieve_response))
		# ~ title = 'Getting Started'
		
		# ~ description = 	'Welcome to SiteSeed: The Freedom to Grow (Blog)|SiteSeed Tools Overview|The Low Down On  Website Creation: Domains, Design, and Hosting (Blog)|SiteSeed Dashboard Walkthrough|Website Builder Walk Through|Get Inspired: Accessing The Template Library|Create Your First Site: Checklist|Selecting a Template to Start With|Starting from Scratch|Editing Your Site| How Many Websites Can I Create?|Building a Free Website|Free vs Premium Sites|Editing Your Site From Your Phone|Adjusting Site Settings|Uploading a Favicon|How to Rename Your Site|How to Duplicate Your Site|How to Delete Your Site Before Publishing'
		# ~ title = 'eCommerce'
		# ~ description = 'Adding eCommerce Functionality To Your Site|Managing Sales|Managing Customers|Using the Shopping Cart Feature|Connecting Payment System'
		# ~ title = 'Forms'
		# ~ description = 'Benefits of Using Forms in Your Website|Managing Individual Site Forms|Exporting Form Content'
		# ~ title = 'Going Live: Publishing & Domains'
		# ~ description = 'Viewing a Preview of Your Site Before Going Live|How to Publish a Site on SiteSeed|Selecting a Site Domain (URL) (blog)|Purchasing a Domain|Renewing a Domain|Linking a Domain You Own|What Are Domain Host Records?|Creating URL Redirects'
		# ~ title = 'Exporting Your Site'
		# ~ description = 'Exporting Your Site|Purchasing More Credits|Uploading Your Export to Wordpress|Uploading Your Export to Shopify|Making Changes to Your Site After Export'
		# ~ title = 'Downgrading & Unpublishing'
		# ~ description = 'How to Unpublish a Site|Premium Feature Changes When Downgrading Your Site'
		# ~ title = 'Integrations'
		# ~ description = 'Benefits of Integrating Email Marketing Tools with Your Website|Benefits of Integrating Webinar Tools with Your Website|Benefits of Integrating eCommerce Tools with Your Website|How to Integrate Shopify|How to Integrate Eucwid|How to Integrate BigCommerce|How to Integrate MailChimp|How to Integrate ActiveCampaign|How to Integrate Hubspot|How to Integrate EasyWebinar|How to Connect Stripe Payments|How to Connect Square Payments'
		# ~ title = 'Adding Contributors & Collaborators'
		# ~ description = 'The Best Resources for Collaborating with Clients on Web Design (Blog)|How to Add Contributors to Your Sites|How to Remove Contributors From Your Sites|Managing Contributor Permissions'
		# ~ title = 'SEO'
		# ~ description = 'Top 2021 SEP Tips (blog)|Hosting Platforms & SEO (blog)|SEO Settings within SiteSeed: Overview|Adding Content for Robotos.txt|Adding Content for Sitemap|Adding Content for Sitemap.xml|Adding Information for Google Site Verification'
		# ~ title = 'Website Design'
		# ~ description = 'Working With Templates'
		# ~ subdescription = 'Selecting The Best Template For Your Purpose|Testing Premium Templates Before Purchasing|Testing eCommerce Templates Before Upgrading|Duplicating a Site That Uses a Premium Template'
		# ~ title = 'Website Design'
		# ~ description = '10 Tips for Managing Multiple Web Designs (blog)|2021 Trends in User Experience (blog)|The Importance of a Logo in Web Design (blog)|The Complete Checklist for Website Design Health in 2021'
		# ~ title = 'Editing Your Site With The Website Builder'
		# ~ description = 'How To Get Started Editing|Builder Tool Overview|Top 5 SiteSeed Builder Features You Should Know About (blog)|General Site Editing|Creating Headers and Footers|Creating New Pages|Deleting Pages|Hiding Pages|Creating Pop Up Forms|Resizing Elements on the Page'
		# ~ title = 'Editing Your Site With The Website Builder'
		# ~ description = 'Grouping Elements|Pinning Elements to the Screen|Using Custom Color Schemes on Your Site|Using Built in Fonts on Your Site|Adding Custom Fonts For Your Site|Editing Content Offline|Keyboard Shortcuts|Saving Your Site'
		# ~ title = 'Roadmap & Feature Releases'
		# ~ description = 'How to Request a New Feature|How to Check In On a Requested Feature|Up Voting a Requested Feature'
		# ~ title = 'Growing After Going Live'
		# ~ description = 'You Published Your Site: What’s Next? (blog)|How to Get The Most Out Of Your Website Blog in 2021 (blog)|Custom Design Requests|1:1 Support for SEO|1:1 Support for Advanced Website Creation|1:1 Support for Lead Generation|1:1 Support for Marketing Strategies and Implementation'
		# ~ title = 'Troubleshooting & FAQ'
		# ~ description = 'General FAQ|SEO and Site Settings FAQ|Going Live Troubleshooting|Custom Code Troubleshooting'
		# ~ title = 'Account & Billing'
		# ~ description = 'Accessing Account and Security Information|Managing Your Subscription|Plans and Features|What Does My Subscription Include?|Upgrading and Downgrading|Cancelling Your Plan|Adding a Payment Method'
		
		

		
		# ~ ss = description.split('|')
		
		# ~ for x in ss:
			# ~ saveFaq = ssFAQs(title=title, description=x, short_description='', url='')
			# ~ saveFaq.save()



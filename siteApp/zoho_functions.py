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

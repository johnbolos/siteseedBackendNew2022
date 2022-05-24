from siteApp.views import *
import time
import subprocess

#GoDaddy Base url
GD_BASE_URL = "https://api.ote-godaddy.com"
Reseller_CID = "3mM44UZC2i4zX1_59377wBZdjLoBUBLtS5WqL"
Reseller_Secret = "3oQtZ9ewwB3QpSEvk2yYrL"
X_Shopper_ID = '1500623385'

LV_GD_BASE_URL = "https://api.godaddy.com"
LV_Reseller_CID = "e42kNkxm5oyG_3KjpMktSfjdsh5ZVkNCDME"
LV_Reseller_Secret = "78xkqRPHD68vPbvJHDCbmY"
LV_X_Shopper_ID = '206227487'


# Modular function
def unassignDomain(request, custID, domain_id, site_id):
	try:
		get_user_sites = userSites.objects.get(id=site_id, domain_id=domain_id)
		get_user_sites.is_domain_connected = 0
		get_user_sites.domain_id = 0
		get_user_sites.save()

		get_general_settings = userGeneralSettings.objects.get(cust_id=custID, user_site_id=site_id)
		get_general_settings.custom_domain = ""
		get_general_settings.save()
		return "Domain unassigned"
	except Exception as err:
		return str(err)


def createConfSettings(domainName, HtmlFolderPath):	
	#post_data = json.loads(request.body)
	#html = post_data['htmlfile']
	#domainName = "tarunsharma.info"
	
	# ~ f = open("/var/www/html/index.html", "w")
	# ~ f.write(html)
	# ~ f.close()
	try:
		conf = 	'''
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName '''+str(domainName)+'''
	ServerAlias ''''www.'+str(domainName)+'''
	DocumentRoot '''+str(HtmlFolderPath)+'''

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
'''
		main_file_name = str(domainName).replace(".", "_")
		conf_flie_path = "/var/www/conf_files/"+main_file_name+".conf"
		domain = open(conf_flie_path, "w")
		domain.write(conf)
		domain.close()
		
		os.chdir("/var/www/conf_files/")	
		remove_existing_file = f"sudo rm /etc/apache2/sites-available/{main_file_name}.conf"
		os.system(remove_existing_file)
		shutil.move(main_file_name+".conf", "/etc/apache2/sites-available")
		
		#os.remove(conf_flie_path)
		#os.chdir("/etc/apache2/sites-available")
		
		
		site_enable_command =  f"sudo a2ensite {main_file_name}.conf"
		restart_apache = "sudo systemctl reload apache2"
		
		#os.system("sudo a2ensite "+str(domainName)+".conf")
		
		exec_cmd_1 = os.system(site_enable_command)
		exec_cmd_2 = os.system(restart_apache)
		
		return "Domain enabled"
	
	except Exception as e:
		return str(e)
	

# Domains Page API's
class UserDomains(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def get(self, request):
		final_response={}
		try:
			custID = request.user.id
			all_domains = []
			get_domains = userDomain.objects.filter(cust_id=custID)
			get_user_sites = userSites.objects.filter(cust_id=custID, is_active=1)
			for domain in get_domains:
				domain_dict = {}
				domain_dict['domain_name'] = domain.domain_name
				domain_dict['domain_id'] = domain.domain_id
				domain_dict['start_date'] = domain.start_date
				domain_dict['expiration_date'] = domain.expiration_date
				domain_dict['auto_renew'] = domain.auto_renew
				domain_dict['is_active'] = domain.is_active	
				domain_dict['server_ip'] = domain.server_ip
				domain_dict['assign_to_site'] = "No"
				for sites in get_user_sites:
					if domain.domain_id == sites.domain_id:
						domain_dict['assign_to_site'] = {"site_id":sites.id, "assigned_site_name":sites.site_name}
					else:
						pass
				all_domains.append(domain_dict)

			unassigned_sites = []
			for u_sites in get_user_sites:
				if u_sites.domain_id == 0 and u_sites.is_domain_connected == 0 and u_sites.is_published == 1:
					unassigned_sites.append( {"site_id":u_sites.id, "site_name":u_sites.site_name} )
				else:
					pass

			final_response['data'] = all_domains
			final_response['unassigned_sites'] = unassigned_sites
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)


class RemoveUserDomains(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			domain_id = int(request.POST['domain_id'])

			get_domains = userDomain.objects.get(cust_id=custID, domain_id=domain_id)
			get_domains.is_active = 0	
			get_domains.save()
			
			get_user_sites = userSites.objects.get(domain_id=domain_id, is_domain_connected=1)
			get_user_sites.is_domain_connected = 0
			get_user_sites.domain_id = 0
			get_user_sites.save()
		
			get_general_settings = userGeneralSettings.objects.get(cust_id=custID, user_site_id=get_user_sites.id)
			get_general_settings.custom_domain = ""
			get_general_settings.save()

			final_response['description'] = "Domain deactivated successfully."
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)


class SearchGodaddyDomains(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			search_domain = str(request.POST['search_domain'])
			payload={}
			headers = {
			'accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': f'sso-key {Reseller_CID}:{Reseller_Secret}'
			}
			search_domain_url = GD_BASE_URL+"/v1/domains/suggest?query="+search_domain+"&waitMs=1000"
			response = requests.request("GET", search_domain_url, headers=headers, data=payload)
			gd_domains = response.json()
			domains_list = []
			
			#domains_list.append(str(search_domain))
			for domain in gd_domains:
				domains_list.append(str(domain['domain']))
			
			dm_array = str(json.dumps(domains_list))
			check_availability = requests.request("POST", GD_BASE_URL+"/v1/domains/available?checkType=FAST", headers=headers, data=dm_array)
			gd_avail_domains = check_availability.json()
			domains_array = []
			avail_msg = "Sorry! searched domain is not available."
			for dm in gd_avail_domains['domains']:
				if str(dm['available']) == "True":
					dm['price'] = int(dm['price']) / 1000000
					domains_array.append(dm)

				if dm['domain'] == search_domain and str(dm['available']) == "True":
					avail_msg = "Yay! Searched domain is available."

			final_response['availability_message'] = avail_msg
			final_response['data'] = {"domains" : domains_array}
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)


class PurchaseGodaddyDomains(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			save_message = ""
			custID = request.user.id
			domain = str(request.POST['domain'])
			cardID = str(request.POST['cardID'])
			
			# fetch user details for billing info
			user_data = custMaster.objects.get(cust_id=custID)
			email = str(user_data.email)
			first_name = str(user_data.first_name)
			last_name = str(user_data.last_name)
			#phone = user_data.phone

			billing_info = userBillingAddress.objects.get(payment_method_id=cardID, cust_id=custID)
			address_line_1 = str(billing_info.address_line_1)
			address_line_2 = str(billing_info.address_line_2)
			city = str(billing_info.city)
			state = str(billing_info.state)
			zipcode = str(billing_info.zipcode)
			country = str(billing_info.country)
			phone_code = country_phone_codes[country]
			phn = str(billing_info.phone)
			phone = f"+{phone_code}.{phn}"
			
			headers = {
			'accept': 'application/json',
			"X-Shopper-Id": X_Shopper_ID,
			'Content-Type': 'application/json',
			'Authorization': f'sso-key {Reseller_CID}:{Reseller_Secret}'
			}
			
			payload = {
						"consent": {
							"agreedAt": str(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")),
							"agreedBy": "me",
							"agreementKeys": [
											"DNRA"
											]
						},
						"contactAdmin": {
									"addressMailing": {
									"address1": "1062 Reeds Bridge Road",
									"address2": "",
									"city": "Conway",
									"country": "US",
									"postalCode": "01341",
									"state": "MA"
									},
									"email": "domains@siteseed.io",
									"fax": "",
									"jobTitle": "",
									"nameFirst": "Greg",
									"nameLast": "Jacoby",
									"nameMiddle": "",
									"organization": "SiteSeed, LLC",
									"phone": "+1.2123139557"
						},
						"contactBilling":{
								"addressMailing": {
								"address1": address_line_1,
								"address2": address_line_2,
								"city": city,
								"country": country,
								"postalCode": zipcode,
								"state": state
								},
								"email": email,
								"fax": "",
								"jobTitle": "",
								"nameFirst": first_name,
								"nameLast": last_name,
								"nameMiddle": "",
								"organization": "",
								"phone": phone
						},

						"contactRegistrant": {
								"addressMailing": {
								"address1": address_line_1,
								"address2": address_line_2,
								"city": city,
								"country": country,
								"postalCode": zipcode,
								"state": state
								},
								"email": email,
								"fax": "",
								"jobTitle": "",
								"nameFirst": first_name,
								"nameLast": last_name,
								"nameMiddle": "",
								"organization": "",
								"phone": phone
						},

						"contactTech": {
								"addressMailing": {
								"address1": "1062 Reeds Bridge Road",
								"address2": "",
								"city": "Conway",
								"country": "US",
								"postalCode": "01341",
								"state": "MA"
								},
								"email": "domains@siteseed.io",
								"fax": "",
								"jobTitle": "",
								"nameFirst": "Greg",
								"nameLast": "Jacoby",
								"nameMiddle": "",
								"organization": "SiteSeed, LLC",
								"phone": "+1.2123139557"
						},
						"domain": domain,
						"period": 1,
						"renewAuto": False
				}

			purchase_domain_url = GD_BASE_URL+"/v1/domains/purchase"
			purchase_req = requests.request("POST", purchase_domain_url, headers=headers, data=json.dumps(payload))
			purchase_response = purchase_req.json()
			try:
				gd_order_id = purchase_response['orderId']
				total_amount = purchase_response['total']

				paymentDetail = userPaymentMethod.objects.get(cust_id=custID, id=cardID)
				cardID = paymentDetail.card_id
				
				stripeDetail = ssStripeCustomers.objects.get(cust_id=custID)
				stripe_id = stripeDetail.stripe_id
				charge_description = f"Domain Purchased - {domain}"

				domain_price = int(total_amount) / 1000000

				# stripe charge for the selected plan
				createCharge = stripe.Charge.create(
				amount= int(domain_price * 100),
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
				history = paymentHistory(cust_id=custID, payment_method_id=paymentDetail.id, charge_id=charge_id, subtotal=decimal.Decimal(domain_price), total=decimal.Decimal(domain_price),description=charge_description, discount=0.00, promo_code="")	
				history.save()

				# retrieve details of domain
				retrieve_domain_url = GD_BASE_URL+"/v1/domains/"+domain
				retrieve_req = requests.request("GET", retrieve_domain_url, headers=headers, data={})
				retrieve_response = retrieve_req.json()
				try:
					current_day = datetime.datetime.now().date()
					if calendar.isleap(current_day.year):
						add_days = 366
					else:
						add_days = 365
					
					try:
						domainId = int(retrieve_response['domainId'])
					except Exception:
						domainId = 0
					#createdAt = str(retrieve_response['createdAt']).split('T')[0]
					#expires = str(retrieve_response['expires']).split('T')[0]
					createdAt = current_day
					expires = current_day + datetime.timedelta(days=add_days)

					# add domain info to user's account
					save_user_domain = userDomain(cust_id=custID, domain_name=domain, domain_id=domainId, start_date=createdAt, expiration_date=expires)
					save_user_domain.save()
					save_message = "Domain saved in user account."
				except Exception as r_err:
					save_message = str(r_err)

				final_response['data'] = purchase_response
				final_response['other_info'] = save_message
				final_response['description'] = f"Domain {domain} purchased successfully."
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = 'success'
			except Exception as err:
				final_response['data'] = purchase_response
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'Bad request. '+str(err)
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)


class AssignDomainToSite(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			domain_id = int(request.POST['domain_id'])
			#domain_name = request.POST['domain_name']
			domain_name = "projectmindfulness.us"
			site_id = int(request.POST['site_id'])
			try:
				existing_site_id = int(request.POST['existing_site_id'])
			except Exception:
				existing_site_id = 0

			# un-assign domain if want to assign to different site
			if existing_site_id > 0:
				unassign_domain = unassignDomain(request, custID, domain_id, existing_site_id)

			get_user_sites = userSites.objects.get(id=site_id)
			get_user_sites.is_domain_connected = 1
			get_user_sites.domain_id = domain_id
			get_user_sites.save()
			
			try:
				get_general_settings = userGeneralSettings.objects.get(cust_id=custID, user_site_id=site_id)
				get_general_settings.custom_domain = str(domain_name)
				get_general_settings.save()
			except userGeneralSettings.DoesNotExist:
				general_settings = userGeneralSettings(cust_id=custID, user_site_id=site_id, custom_domain=str(domain_name))
				general_settings.save()

			# create conf file for server and domain
			create_conf_file = createConfSettings(domain_name, get_user_sites.folder_path)

			# update DNS record on Godaddy
			# headers = {
			# 'accept': 'application/json',
			# "X-Shopper-Id": X_Shopper_ID,
			# 'Content-Type': 'application/json',
			# 'Authorization': f'sso-key {Reseller_CID}:{Reseller_Secret}'
			# }

			headers = {
			'accept': 'application/json',
			"X-Shopper-Id": LV_X_Shopper_ID,
			'Content-Type': 'application/json',
			'Authorization': f'sso-key {LV_Reseller_CID}:{LV_Reseller_Secret}'
			}

			# payload = [
			# 	{
			# 		"data": "159.65.145.117",
			# 		"name": domain_name,
			# 		"ttl": 600,
			# 		"type": "A" 
			# 	},
			# 	{
			# 		"data": "ns01.ote.domaincontrol.com",
			# 		"name": "@",
			# 		"ttl": 3600,
			# 		"type": "NS"
			# 	},
			# 	{
			# 		"data": "ns02.ote.domaincontrol.com",
			# 		"name": "@",
			# 		"ttl": 3600,
			# 		"type": "NS"
			# 	}
			# ]

			payload = [
				{
					"data": "159.65.145.117",
					"name": domain_name,
					"ttl": 600,
					"type": "A" 
				},
				{
					"data": "ns01.domaincontrol.com",
					"name": "@",
					"ttl": 3600,
					"type": "NS"
				},
				{
					"data": "ns02.domaincontrol.com",
					"name": "@",
					"ttl": 3600,
					"type": "NS"
				}
			]
			update_dns_url = f"{LV_GD_BASE_URL}/v1/domains/{domain_name}/records"
			update_dns_req = requests.request("PUT", update_dns_url, headers=headers, data=json.dumps(payload))
			try:
				update_dns_response = update_dns_req.json()
				final_response['dns'] = update_dns_response
			except Exception:
				final_response['dns'] = update_dns_req	

			final_response['conf'] = create_conf_file
			final_response['description'] = "Domain assigned to site successfully."
			final_response['status'] = status.HTTP_200_OK	
			final_response['message'] = 'success'
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)	


class UnAssignDomainFromSite(APIView):
	permission_classes = [TokenHasReadWriteScope]
	
	def post(self, request):
		final_response={}
		try:
			custID = request.user.id
			domain_id = int(request.POST['domain_id'])
			site_id = int(request.POST['site_id'])

			unassign_domain = unassignDomain(request, custID, domain_id, site_id)

			if unassign_domain == "Domain unassigned":
				final_response['description'] = unassign_domain
				final_response['status'] = status.HTTP_200_OK	
				final_response['message'] = 'success'
			else:
				final_response['status'] = status.HTTP_400_BAD_REQUEST	
				final_response['message'] = 'Bad request. '+str(unassign_domain)
		
		except Exception as err:
			final_response['status'] = status.HTTP_400_BAD_REQUEST	
			final_response['message'] = 'Bad request. '+str(err)
		
		return Response(final_response)
		
		
def testDomain(request):
	
	os.chdir("/etc/apache2/sites-available/")	
	os.system("sudo a2ensite projectmindfulness_us.conf")
	# ~ shutil.move("projectmindfulness_us.conf", "/etc/apache2/sites-enabled")
	
	# ~ os.chdir("/etc/apache2/sites-available")
	# ~ os.chdir("cp projectmindfulness_us.conf /etc/apache2/sites-enabled")	
	# ~ shutil.move("projectmindfulness_us.conf", "/etc/apache2/sites-enabled")

	d = os.system("sudo systemctl reload apache2")
	return HttpResponse(d)

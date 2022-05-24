from datetime import datetime
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User, Group
from time import strftime
import datetime
import time

class custMaster(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	first_name = models.CharField(default='null', max_length=250)
	last_name = models.CharField(default='null', max_length=250)
	email = models.CharField(default='null',max_length=250)
	phone = models.CharField(default='null',max_length=250)
	display_name = models.CharField(default='null',max_length=250)
	forgot_pswd_status = models.IntegerField(default=0, blank=True)
	profile_picture = models.ImageField(upload_to='profile_pics', default="default-profile.png")
	bio = models.CharField(max_length=500, default="null")
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	
	def __str__(self):
		return self.custID        

	class Meta:
		db_table = 'cust_master'

class ssTemplates(models.Model):
	template_name = models.CharField(max_length=250)
	path = models.CharField(max_length=250)
	thumbnail = models.ImageField(upload_to='template_thumbs', default="default-thumb.jpg")
	template_type = models.CharField(default="Free", max_length=100)
	price = models.DecimalField(default=0.00, max_digits=5, decimal_places=2)
	is_active = models.IntegerField(default=1)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_templates'

class ssWebsiteType(models.Model):
	site_name = models.CharField(max_length=250)
	is_active = models.IntegerField(default=1)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_website_type'

class ssSubscriptionPlans(models.Model):
	plan_name_monthly = models.CharField(max_length=250)
	plan_name_yearly = models.CharField(max_length=250)
	plan_type = models.CharField(max_length=250)
	description = models.CharField(max_length=250)
	price_monthly = models.DecimalField(default=0.00, max_digits=10, decimal_places=2)
	price_yearly = models.DecimalField(default=0.00, max_digits=10, decimal_places=2)
	validity = models.CharField(max_length=100)
	is_active = models.IntegerField(default=1)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_subscription_plans'
		

class ssStripeCustomers(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	stripe_id = models.CharField(max_length=250, blank=True, null=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_stripe_customers'

class userPaymentMethod(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	card_id = models.CharField(default='', blank=True, max_length=50)
	last4 = models.CharField(max_length=4)
	exp_month = models.CharField(max_length=2)
	exp_year = models.CharField(max_length=4)
	brand = models.CharField(max_length=20, default="Visa")
	is_default = models.IntegerField(default=1)
	is_active = models.IntegerField(default=1)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_payment_method'		

class userSites(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	site_name = models.CharField(default='null', max_length=250)
	template_id = models.IntegerField(default=0, blank=True)
	is_active = models.IntegerField(default=0, blank=True)
	is_published = models.IntegerField(default=0, blank=True)
	is_domain_connected = models.IntegerField(default=0, blank=True)
	domain_id = models.IntegerField(default=0, blank=True)
	json_path = models.CharField(default='', blank=True, max_length=250)
	folder_path = models.CharField(default='', blank=True, max_length=250)
	site_website_type_id = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_sites'		

class userSubscriptionPlan(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	subscription_plan_id = models.IntegerField(default=0, blank=True)
	zoho_customer_id = models.CharField(default='null', max_length=250)
	zoho_subscription_id = models.CharField(default='null', max_length=250)
	zoho_subscription_name = models.CharField(default='null', max_length=250)
	start_date = models.DateField(auto_now_add=True)
	end_date = models.DateField(null=True, blank=True)
	next_billing = models.DateField(null=True, blank=True)
	plan_validity = models.CharField(default='monthly', max_length=50)
	is_active = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_subscription_plan'		

class ssSubscriptionPlansDetails(models.Model):
	ss_subscription_plans_id = models.IntegerField(default=0, blank=True)
	name = models.CharField(max_length=250)
	total_sites = models.IntegerField(default=0, blank=True)
	total_export_credits = models.IntegerField(default=0, blank=True)
	features = models.TextField()
	is_active = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_subscription_plans_details'	
		
class userBillingAddress(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	payment_method_id = models.IntegerField(default=0, blank=True)
	address_line_1 = models.CharField(max_length=250)
	address_line_2 = models.CharField(max_length=250)
	phone = models.CharField(max_length=10, null=True, blank=True)
	city = models.CharField(max_length=250)
	state = models.CharField(max_length=250)
	zipcode = models.CharField(max_length=10)
	country = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_billing_address'	
		
class paymentHistory(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	payment_method_id = models.CharField(max_length=250, blank=True, null=True)
	charge_id = models.CharField(max_length=250, blank=True, null=True)
	subtotal = models.DecimalField(default=0.00, max_digits=10, decimal_places=2)
	discount = models.DecimalField(default=0.00, max_digits=5, decimal_places=2)
	tax = models.DecimalField(default=0.00, max_digits=5, decimal_places=2)
	total = models.DecimalField(default=0.00, max_digits=10, decimal_places=2)
	description = models.CharField(max_length=500, blank=True, null=True)
	promo_code = models.CharField(max_length=150, blank=True, null=True)
	subscription_id = models.CharField(max_length=250, blank=True, null=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)


	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'payment_history'	

class notifications(models.Model):
	name = models.CharField(max_length=250)
	is_active = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'notifications'

class userNotificationSettings(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	notifications_id = models.IntegerField(default=0, blank=True) 
	setting = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_notification_settings'	
		
class userDomain(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	domain_name = models.CharField(max_length=250)
	domain_id = models.IntegerField(default=0, blank=True)
	start_date = models.DateField(null=True, blank=True)
	expiration_date = models.DateField(null=True, blank=True)
	server_ip = models.CharField(max_length=250, blank=True)
	auto_renew = models.IntegerField(default=0, blank=True)
	is_active = models.IntegerField(default=1, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_domain'	
		
class userDomainHost(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	domain_id = models.IntegerField(default=0, blank=True)
	server_ip = models.CharField(max_length=250)
	path = models.CharField(max_length=250)
	conf_settings = models.CharField(max_length=250)
	is_active = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_domain_host'	
		
class userGeneralSettings(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	user_site_id = models.IntegerField(default=0, blank=True)
	project_name = models.CharField(default='null', max_length=250)
	favicon = models.ImageField(upload_to='fav_icons', default="default-favicon.png")
	siteseed_branding = models.IntegerField(default=1, blank=True)
	sub_domain = models.CharField(default='null', max_length=250)
	custom_domain = models.CharField(default='null', max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_general_settings'	
		
class userSeoSettings(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	user_site_id = models.IntegerField(default=0, blank=True)
	robots_txt = models.CharField(max_length=250)
	sitemap = models.CharField(max_length=250)
	sitemap_xml = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_seo_settings'	
		
class userFormsSettings(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	user_site_id = models.IntegerField(default=0, blank=True)	
	form_name = models.CharField(max_length=250)
	submition_to_address = models.CharField(max_length=250)
	subject_line = models.CharField(max_length=250)
	reply_address = models.CharField(max_length=250)
	form_submission_count = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_forms_settings'	
		
class userFontsSettings(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	user_site_id = models.IntegerField(default=0, blank=True)
	custom_fonts = models.CharField(max_length=250)
	adobe_fonts_key = models.CharField(max_length=250)	
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_fonts_settings'	
		
class userBackupSettings(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	user_site_id = models.IntegerField(default=0, blank=True)
	backup_path = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_backup_settings'


class ssLatestOffers(models.Model):
	title =  models.CharField(max_length=250)
	description = models.CharField(max_length=250)
	shortDescription = models.CharField(max_length=250)
	startDate = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	endDate = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	isActive = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	
	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_latest_offers'
		
class ssRoadmapReleases(models.Model):
	title =  models.CharField(max_length=250)
	description = models.CharField(max_length=250)
	updateType = models.CharField(max_length=250)
	releaseDate = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)	
	isActive = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:	
		db_table = 'ss_roadmap_releases'

class userExports(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	site_name = models.CharField(max_length=250)
	platform = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:	
		db_table = 'user_exports'	

class userSiteContributors(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	user_site_id = models.IntegerField(default=0, blank=True)
	name = models.CharField(max_length=250)
	email = models.CharField(max_length=250)
	role_id = models.IntegerField(default=1, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:	
		db_table = 'user_site_contributors'			


class contributorRolePermission(models.Model):
	role = models.CharField(max_length=250)
	can_edit = models.IntegerField(default=0, blank=True)
	can_preview = models.IntegerField(default=0, blank=True)
	edit_members = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:	
		db_table = 'contributor_role_permissions'		


class ssFAQs(models.Model):
	title = models.CharField(max_length=250)
	description = models.TextField()
	short_description = models.TextField()
	url = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_faq'	


class zohoAuthToken(models.Model):
	access_token = models.CharField(max_length=250, blank=True)
	refresh_token = models.CharField(max_length=250, blank=True)
	api_domain = models.CharField(max_length=100, blank=True)
	token_type = models.CharField(max_length=50, blank=True)
	expires_in = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'zoho_auth_token'	


class ssPromoCodes(models.Model):
	code = models.CharField(max_length=250, blank=True)
	description = models.CharField(max_length=250, blank=True)
	discount_price = models.DecimalField(default=0.00, max_digits=5, decimal_places=2)
	start_date = models.DateField(auto_now_add=True)
	end_date = models.DateField(null=True, blank=True)
	is_active = models.IntegerField(default=0, blank=True)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)
	updatedOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'ss_promo_codes'


class userPurchasedTemplates(models.Model):
	cust_id = models.IntegerField(default=0, blank=True)
	template_id = models.CharField(max_length=250, blank=True)
	template_name = models.CharField(max_length=250, blank=True)
	purchased_on = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'user_purchased_templates'


class betaTesters(models.Model):
	email = models.CharField(max_length=250)
	security_code = models.CharField(max_length=250)
	createdOn = models.DateTimeField(null=True, default=datetime.datetime.now(), blank=True)

	def __str__(self):
		return self.id        

	class Meta:
		db_table = 'beta_testers'

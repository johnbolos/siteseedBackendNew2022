from rest_framework import routers
from django.conf import settings
from django.conf.urls.static import static
from siteApp import views
from siteApp import user_domains
from django.urls import path, include, re_path

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'groups', views.GroupViewSet)

urlpatterns = [

		path('', include(router.urls)),
		path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
		path('login/', views.emailAuth, name='login'),
		path('forgot-password/', views.forgotPassword, name='forgot-password'),
		path('reset-password/', views.resetPassword, name='reset-password'),
		path('index/', views.Index.as_view(), name='indexs'),
		path('zoho-token/', views.zohoGrantToken.as_view(), name='zoho-token'),
		path('google-login/', views.google_login, name="google-login"),
		path('signup/', views.createUserAccount, name="signup"),
		path('logout/', views.Logout.as_view(), name="logout"),
		

		# main api urls
		path('dashboard-api/', views.DashboardAPI.as_view(), name="dashboard-api"),
		path('user-profile/', views.UserProfile.as_view(), name="user-profile"),
		path('user-notification-settings/', views.UserNotificationSettings.as_view(), name="notification-settings"),
		path('change-password/', views.ChangePassword.as_view(), name="change-password"),
		path('general-settings/', views.SiteGeneralSettings.as_view(), name="general-settings"),
		path('seo-settings/', views.SiteSEOSettings.as_view(), name="seo-settings"),
		path('form-settings/site_id/<int:siteID>/', views.GetSiteFormSettings.as_view(), name="get-form-settings"),
		path('form-settings/', views.SiteFormSettings.as_view(), name="form-settings"),
		path('fonts-settings/site_id/<int:siteID>/', views.GetSiteFontsSettings.as_view(), name="get-fonts-settings"),
		path('fonts-settings/', views.SiteFontsSettings.as_view(), name="font-settings"),
		path('site-backups/', views.SiteBackups.as_view(), name="site-backups"),
		path('site-contributors/', views.SiteContributors.as_view(), name="site-contributors"),

		path('billing-information/', views.BillingInformation.as_view(), name="billing-information"),
		path('add-card/', views.AddPaymemtMethod.as_view(), name="add-card"),
		path('update-card/', views.UpdatePaymemtMethod.as_view(), name="update-card"),
		
		path('user-subscription/', views.UserSubscription.as_view(), name="user-subscription"),
		path('change-plan/', views.ChangeUserPlan.as_view(), name="change-plan"),

		path('search/', views.SearchBarFilter.as_view(), name="search-filter"),

		path('create-site/', views.CreateSite.as_view(), name="create-site"),
		path('delete-site/', views.DeleteUserSite.as_view(), name="delete-site"),
		path('save-site-path/', views.SaveSitePath.as_view(), name="save-site-path"),
		path('purchase-template/', views.PurchaseTemplate.as_view(), name="purchase-template"),
		path('check-promo-code/', views.CheckPromoCode.as_view(), name="check-promo-code"),
		path('test/', views.test.as_view(), name="test"),

		path('ss-templates/', views.SiteseedTemplates.as_view(), name="ss-templates"),
		path('save-template-to-site/', views.SaveTemplateToSite.as_view(), name="save-template-to-site"),


		path('articles-saerch/', views.zohoDeskSearchArticles, name="articles-saerch"),
		path('billing-history/', views.BillingHistory.as_view(), name="billing-history"),
		path('save-export/', views.UserExports.as_view(), name="save-export"),

		path('save-files/', views.saveSiteFiles.as_view(), name="save-files"),

		#Get Go-daddy domains
		path('user-domains/', user_domains.UserDomains.as_view(), name="user-domains"),
		path('remove-domain/', user_domains.RemoveUserDomains.as_view(), name="remove-domain"),
		path('search-domain/', user_domains.SearchGodaddyDomains.as_view(), name="search-domain"),
		path('purchase-domain/', user_domains.PurchaseGodaddyDomains.as_view(), name="purchase-domain"),
		path('assign-domain/', user_domains.AssignDomainToSite.as_view(), name="assign-domain"),
		path('unassign-domain/', user_domains.UnAssignDomainFromSite.as_view(), name="unassign-domain"),
		path('test-domain/', user_domains.testDomain, name="test-domain"),
		

		path('beta-code/', views.BetaCodeGenerator.as_view(), name="beta-code"),


		#productStash Roadmap
		path('roadmap/', views.roadMap.as_view(), name="roadmap"),
		path('roadmapCards/', views.roadMapCard.as_view(), name="roadmap-cards"),
		
]

if settings.DEBUG: 
        urlpatterns += static(settings.MEDIA_URL, 
                              document_root=settings.MEDIA_ROOT) 
#handler404 = views.Handle_404_Error


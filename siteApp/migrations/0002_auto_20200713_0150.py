# Generated by Django 2.2 on 2020-07-13 01:50

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siteApp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='custDomainDetails',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('custserviceID', models.IntegerField()),
                ('hostingDomainID', models.IntegerField()),
                ('domainName', models.CharField(max_length=250)),
                ('domainIP', models.CharField(max_length=250)),
                ('domainType', models.CharField(max_length=250)),
                ('domainDNS', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 267104))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 267150))),
            ],
            options={
                'db_table': 'cust_domain_details',
            },
        ),
        migrations.CreateModel(
            name='custHostingDetails',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('custserviceID', models.IntegerField()),
                ('hostingDomainID', models.IntegerField()),
                ('hostingName', models.CharField(max_length=250)),
                ('hostingIP', models.CharField(max_length=250)),
                ('username', models.CharField(max_length=250)),
                ('password', models.CharField(max_length=250)),
                ('path', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 266322))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 266367))),
            ],
            options={
                'db_table': 'cust_hosting_details',
            },
        ),
        migrations.CreateModel(
            name='custHostingDomains',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('custserviceID', models.IntegerField()),
                ('domainName', models.CharField(max_length=250)),
                ('domainIP', models.CharField(max_length=250)),
                ('hostingIP', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 265541))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 265591))),
            ],
            options={
                'db_table': 'cust_hosting_domains',
            },
        ),
        migrations.CreateModel(
            name='custMaster',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('firstName', models.CharField(max_length=250)),
                ('lastName', models.CharField(max_length=250)),
                ('email', models.CharField(max_length=250)),
                ('phone', models.CharField(max_length=250)),
                ('forgotpswdStatus', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 262218))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 262276))),
            ],
            options={
                'db_table': 'cust_master',
            },
        ),
        migrations.CreateModel(
            name='custService',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('serviceTypeID', models.IntegerField()),
                ('serviceName', models.CharField(max_length=250)),
                ('ssHosting', models.CharField(max_length=250)),
                ('ssDomain', models.CharField(max_length=250)),
                ('tpHosting', models.CharField(max_length=250)),
                ('tpDomain', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 263906))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 263955))),
            ],
            options={
                'db_table': 'cust_service',
            },
        ),
        migrations.CreateModel(
            name='custStaticSite',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('templateID', models.IntegerField()),
                ('hostingDomainID', models.IntegerField()),
                ('html', models.TextField()),
                ('css', models.TextField()),
                ('path', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 268756))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 268805))),
            ],
            options={
                'db_table': 'cust_static_site',
            },
        ),
        migrations.CreateModel(
            name='custWpTheme',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('templateID', models.IntegerField()),
                ('hostingDomainID', models.IntegerField()),
                ('css', models.TextField()),
                ('path', models.CharField(max_length=250)),
                ('header', models.TextField()),
                ('body', models.TextField()),
                ('footer', models.TextField()),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 269553))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 269600))),
            ],
            options={
                'db_table': 'cust_wp_theme',
            },
        ),
        migrations.CreateModel(
            name='location',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('address', models.CharField(max_length=250)),
                ('city', models.CharField(max_length=250)),
                ('state', models.CharField(max_length=100)),
                ('country', models.CharField(max_length=100)),
                ('zipCode', models.CharField(max_length=10)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 263083))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 263130))),
            ],
            options={
                'db_table': 'cust_location',
            },
        ),
        migrations.CreateModel(
            name='orderMaster',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('paymentID', models.IntegerField()),
                ('chargeID', models.IntegerField()),
                ('orderName', models.CharField(max_length=250)),
                ('description', models.CharField(max_length=250)),
                ('price', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 271092))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 271139))),
            ],
            options={
                'db_table': 'order_master',
            },
        ),
        migrations.CreateModel(
            name='paymentMethod',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('custID', models.IntegerField()),
                ('stripeID', models.IntegerField()),
                ('last4', models.CharField(max_length=4)),
                ('expMonth', models.CharField(max_length=2)),
                ('expYear', models.CharField(max_length=4)),
                ('isDefault', models.IntegerField(default=1)),
                ('isActive', models.IntegerField(default=1)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 270328))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 270375))),
            ],
            options={
                'db_table': 'payment_method',
            },
        ),
        migrations.CreateModel(
            name='ssServiceType',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('siteType', models.CharField(max_length=250)),
                ('siteName', models.CharField(max_length=250)),
                ('isActive', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 264660))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 264711))),
            ],
            options={
                'db_table': 'ss_service_type',
            },
        ),
        migrations.CreateModel(
            name='ssTemplates',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('templateName', models.CharField(max_length=250)),
                ('templateType', models.CharField(max_length=250)),
                ('html', models.TextField()),
                ('css', models.TextField()),
                ('templatePrice', models.CharField(max_length=250)),
                ('isActive', models.CharField(max_length=250)),
                ('createdBy', models.CharField(max_length=50)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 267944))),
                ('updatedBy', models.CharField(max_length=50)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2020, 7, 13, 1, 50, 49, 267990))),
            ],
            options={
                'db_table': 'ss_templates',
            },
        ),
        migrations.DeleteModel(
            name='userSite',
        ),
    ]

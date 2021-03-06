# Generated by Django 3.1.5 on 2021-03-22 08:49

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siteApp', '0062_auto_20210318_0859'),
    ]

    operations = [
        migrations.CreateModel(
            name='ssPromoCodes',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(blank=True, max_length=250)),
                ('description', models.CharField(blank=True, max_length=250)),
                ('discount_price', models.DecimalField(decimal_places=2, default=0.0, max_digits=5)),
                ('start_date', models.DateField(auto_now_add=True)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('is_active', models.IntegerField(blank=True, default=0)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 464675), null=True)),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 464728), null=True)),
            ],
            options={
                'db_table': 'ss_promo_codes',
            },
        ),
        migrations.AlterField(
            model_name='contributorrolepermission',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 460972), null=True),
        ),
        migrations.AlterField(
            model_name='contributorrolepermission',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 461029), null=True),
        ),
        migrations.AlterField(
            model_name='custmaster',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 440346), null=True),
        ),
        migrations.AlterField(
            model_name='custmaster',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 440388), null=True),
        ),
        migrations.AlterField(
            model_name='notifications',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 450572), null=True),
        ),
        migrations.AlterField(
            model_name='notifications',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 450609), null=True),
        ),
        migrations.AlterField(
            model_name='paymenthistory',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 449654), null=True),
        ),
        migrations.AlterField(
            model_name='paymenthistory',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 449684), null=True),
        ),
        migrations.AlterField(
            model_name='ssfaqs',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 462150), null=True),
        ),
        migrations.AlterField(
            model_name='ssfaqs',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 462212), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 457634), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='endDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 457565), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='startDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 457508), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 457673), null=True),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 458411), null=True),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='releaseDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 458365), null=True),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 458432), null=True),
        ),
        migrations.AlterField(
            model_name='ssstripecustomers',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 444309), null=True),
        ),
        migrations.AlterField(
            model_name='ssstripecustomers',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 444340), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplans',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 443523), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplans',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 443582), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplansdetails',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 448008), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplansdetails',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 448038), null=True),
        ),
        migrations.AlterField(
            model_name='sstemplates',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 441735), null=True),
        ),
        migrations.AlterField(
            model_name='sstemplates',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 441765), null=True),
        ),
        migrations.AlterField(
            model_name='sswebsitetype',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 442718), null=True),
        ),
        migrations.AlterField(
            model_name='sswebsitetype',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 442749), null=True),
        ),
        migrations.AlterField(
            model_name='userbackupsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 456796), null=True),
        ),
        migrations.AlterField(
            model_name='userbackupsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 456827), null=True),
        ),
        migrations.AlterField(
            model_name='userbillingaddress',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 448862), null=True),
        ),
        migrations.AlterField(
            model_name='userbillingaddress',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 448893), null=True),
        ),
        migrations.AlterField(
            model_name='userdomain',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 451970), null=True),
        ),
        migrations.AlterField(
            model_name='userdomain',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 451999), null=True),
        ),
        migrations.AlterField(
            model_name='userdomainhost',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 452811), null=True),
        ),
        migrations.AlterField(
            model_name='userdomainhost',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 452841), null=True),
        ),
        migrations.AlterField(
            model_name='userexports',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 459011), null=True),
        ),
        migrations.AlterField(
            model_name='userexports',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 459043), null=True),
        ),
        migrations.AlterField(
            model_name='userfontssettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 456068), null=True),
        ),
        migrations.AlterField(
            model_name='userfontssettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 456098), null=True),
        ),
        migrations.AlterField(
            model_name='userformssettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 455308), null=True),
        ),
        migrations.AlterField(
            model_name='userformssettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 455339), null=True),
        ),
        migrations.AlterField(
            model_name='usergeneralsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 453544), null=True),
        ),
        migrations.AlterField(
            model_name='usergeneralsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 453574), null=True),
        ),
        migrations.AlterField(
            model_name='usernotificationsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 451142), null=True),
        ),
        migrations.AlterField(
            model_name='usernotificationsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 451171), null=True),
        ),
        migrations.AlterField(
            model_name='userpaymentmethod',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 445094), null=True),
        ),
        migrations.AlterField(
            model_name='userpaymentmethod',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 445124), null=True),
        ),
        migrations.AlterField(
            model_name='userseosettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 454465), null=True),
        ),
        migrations.AlterField(
            model_name='userseosettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 454495), null=True),
        ),
        migrations.AlterField(
            model_name='usersitecontributors',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 459871), null=True),
        ),
        migrations.AlterField(
            model_name='usersitecontributors',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 459923), null=True),
        ),
        migrations.AlterField(
            model_name='usersites',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 445836), null=True),
        ),
        migrations.AlterField(
            model_name='usersites',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 445865), null=True),
        ),
        migrations.AlterField(
            model_name='usersubscriptionplan',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 447103), null=True),
        ),
        migrations.AlterField(
            model_name='usersubscriptionplan',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 447133), null=True),
        ),
        migrations.AlterField(
            model_name='zohoauthtoken',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 463428), null=True),
        ),
        migrations.AlterField(
            model_name='zohoauthtoken',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 22, 8, 49, 19, 463489), null=True),
        ),
    ]

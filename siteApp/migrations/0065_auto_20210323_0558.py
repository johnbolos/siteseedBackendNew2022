# Generated by Django 3.1.5 on 2021-03-23 05:58

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siteApp', '0064_auto_20210322_0855'),
    ]

    operations = [
        migrations.CreateModel(
            name='userPurchasedTemplates',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cust_id', models.IntegerField(blank=True, default=0)),
                ('template_id', models.CharField(blank=True, max_length=250)),
                ('template_name', models.CharField(blank=True, max_length=250)),
                ('purchased_on', models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 275661), null=True)),
            ],
            options={
                'db_table': 'user_purchased_templates',
            },
        ),
        migrations.AlterField(
            model_name='contributorrolepermission',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 272758), null=True),
        ),
        migrations.AlterField(
            model_name='contributorrolepermission',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 272789), null=True),
        ),
        migrations.AlterField(
            model_name='custmaster',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 244719), null=True),
        ),
        migrations.AlterField(
            model_name='custmaster',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 244797), null=True),
        ),
        migrations.AlterField(
            model_name='notifications',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 261363), null=True),
        ),
        migrations.AlterField(
            model_name='notifications',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 261417), null=True),
        ),
        migrations.AlterField(
            model_name='paymenthistory',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 260166), null=True),
        ),
        migrations.AlterField(
            model_name='paymenthistory',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 260217), null=True),
        ),
        migrations.AlterField(
            model_name='ssfaqs',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 273403), null=True),
        ),
        migrations.AlterField(
            model_name='ssfaqs',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 273434), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 269753), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='endDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 269713), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='startDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 269682), null=True),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 269773), null=True),
        ),
        migrations.AlterField(
            model_name='sspromocodes',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 274774), null=True),
        ),
        migrations.AlterField(
            model_name='sspromocodes',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 274804), null=True),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 270686), null=True),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='releaseDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 270639), null=True),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 270708), null=True),
        ),
        migrations.AlterField(
            model_name='ssstripecustomers',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 251071), null=True),
        ),
        migrations.AlterField(
            model_name='ssstripecustomers',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 251129), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplans',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 249867), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplans',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 249949), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplansdetails',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 256804), null=True),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplansdetails',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 256859), null=True),
        ),
        migrations.AlterField(
            model_name='sstemplates',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 246827), null=True),
        ),
        migrations.AlterField(
            model_name='sstemplates',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 246911), null=True),
        ),
        migrations.AlterField(
            model_name='sswebsitetype',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 248618), null=True),
        ),
        migrations.AlterField(
            model_name='sswebsitetype',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 248672), null=True),
        ),
        migrations.AlterField(
            model_name='userbackupsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 268961), null=True),
        ),
        migrations.AlterField(
            model_name='userbackupsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 269000), null=True),
        ),
        migrations.AlterField(
            model_name='userbillingaddress',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 258453), null=True),
        ),
        migrations.AlterField(
            model_name='userbillingaddress',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 258499), null=True),
        ),
        migrations.AlterField(
            model_name='userdomain',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 263062), null=True),
        ),
        migrations.AlterField(
            model_name='userdomain',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 263092), null=True),
        ),
        migrations.AlterField(
            model_name='userdomainhost',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 264042), null=True),
        ),
        migrations.AlterField(
            model_name='userdomainhost',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 264074), null=True),
        ),
        migrations.AlterField(
            model_name='userexports',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 271452), null=True),
        ),
        migrations.AlterField(
            model_name='userexports',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 271485), null=True),
        ),
        migrations.AlterField(
            model_name='userfontssettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 268187), null=True),
        ),
        migrations.AlterField(
            model_name='userfontssettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 268233), null=True),
        ),
        migrations.AlterField(
            model_name='userformssettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 267276), null=True),
        ),
        migrations.AlterField(
            model_name='userformssettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 267307), null=True),
        ),
        migrations.AlterField(
            model_name='usergeneralsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 265193), null=True),
        ),
        migrations.AlterField(
            model_name='usergeneralsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 265252), null=True),
        ),
        migrations.AlterField(
            model_name='usernotificationsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 262263), null=True),
        ),
        migrations.AlterField(
            model_name='usernotificationsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 262295), null=True),
        ),
        migrations.AlterField(
            model_name='userpaymentmethod',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 252330), null=True),
        ),
        migrations.AlterField(
            model_name='userpaymentmethod',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 252380), null=True),
        ),
        migrations.AlterField(
            model_name='userseosettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 266507), null=True),
        ),
        migrations.AlterField(
            model_name='userseosettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 266539), null=True),
        ),
        migrations.AlterField(
            model_name='usersitecontributors',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 272104), null=True),
        ),
        migrations.AlterField(
            model_name='usersitecontributors',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 272133), null=True),
        ),
        migrations.AlterField(
            model_name='usersites',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 253609), null=True),
        ),
        migrations.AlterField(
            model_name='usersites',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 253660), null=True),
        ),
        migrations.AlterField(
            model_name='usersubscriptionplan',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 255108), null=True),
        ),
        migrations.AlterField(
            model_name='usersubscriptionplan',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 255169), null=True),
        ),
        migrations.AlterField(
            model_name='zohoauthtoken',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 274084), null=True),
        ),
        migrations.AlterField(
            model_name='zohoauthtoken',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 3, 23, 5, 58, 2, 274114), null=True),
        ),
    ]

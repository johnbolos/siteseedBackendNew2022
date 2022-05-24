# Generated by Django 2.1 on 2021-01-11 10:12

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('siteApp', '0004_auto_20210111_0515'),
    ]

    operations = [
        migrations.CreateModel(
            name='notifications',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250)),
                ('is_active', models.CharField(max_length=250)),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 456286))),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 456322))),
            ],
            options={
                'db_table': 'notifications',
            },
        ),
        migrations.CreateModel(
            name='userNotificationSettings',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cust_id', models.IntegerField()),
                ('notifications_id', models.IntegerField()),
                ('setting', models.IntegerField()),
                ('createdOn', models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 456973))),
                ('updatedOn', models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 457004))),
            ],
            options={
                'db_table': 'user_notification_settings',
            },
        ),
        migrations.DeleteModel(
            name='notificationSettings',
        ),
        migrations.AddField(
            model_name='custmaster',
            name='bio',
            field=models.CharField(default='null', max_length=500),
        ),
        migrations.AddField(
            model_name='custmaster',
            name='profile_picture',
            field=models.ImageField(default='null', upload_to='profile_pics'),
        ),
        migrations.AlterField(
            model_name='custmaster',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 447256)),
        ),
        migrations.AlterField(
            model_name='custmaster',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 447293)),
        ),
        migrations.AlterField(
            model_name='orderdetail',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 455548)),
        ),
        migrations.AlterField(
            model_name='orderdetail',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 455584)),
        ),
        migrations.AlterField(
            model_name='ordermaster',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 454651)),
        ),
        migrations.AlterField(
            model_name='ordermaster',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 454681)),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 465014)),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='endDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 464972)),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='startDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 464940)),
        ),
        migrations.AlterField(
            model_name='sslatestoffers',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 465039)),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 465979)),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='releaseDate',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 465923)),
        ),
        migrations.AlterField(
            model_name='ssroadmapreleases',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 466006)),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplans',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 449700)),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplans',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 449741)),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplansdetails',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 453129)),
        ),
        migrations.AlterField(
            model_name='sssubscriptionplansdetails',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 453166)),
        ),
        migrations.AlterField(
            model_name='sstemplates',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 448308)),
        ),
        migrations.AlterField(
            model_name='sstemplates',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 448339)),
        ),
        migrations.AlterField(
            model_name='sswebsitetype',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 448912)),
        ),
        migrations.AlterField(
            model_name='sswebsitetype',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 448942)),
        ),
        migrations.AlterField(
            model_name='userbackupsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 464194)),
        ),
        migrations.AlterField(
            model_name='userbackupsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 464225)),
        ),
        migrations.AlterField(
            model_name='userbillingaddress',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 453919)),
        ),
        migrations.AlterField(
            model_name='userbillingaddress',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 453949)),
        ),
        migrations.AlterField(
            model_name='userdomain',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 457795)),
        ),
        migrations.AlterField(
            model_name='userdomain',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 457830)),
        ),
        migrations.AlterField(
            model_name='userdomainhost',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 458643)),
        ),
        migrations.AlterField(
            model_name='userdomainhost',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 458672)),
        ),
        migrations.AlterField(
            model_name='userfontssettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 463471)),
        ),
        migrations.AlterField(
            model_name='userfontssettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 463502)),
        ),
        migrations.AlterField(
            model_name='userformssettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 462651)),
        ),
        migrations.AlterField(
            model_name='userformssettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 462694)),
        ),
        migrations.AlterField(
            model_name='usergeneralsettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 461038)),
        ),
        migrations.AlterField(
            model_name='usergeneralsettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 461071)),
        ),
        migrations.AlterField(
            model_name='userpaymentmethod',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 450674)),
        ),
        migrations.AlterField(
            model_name='userpaymentmethod',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 450714)),
        ),
        migrations.AlterField(
            model_name='userseosettings',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 461826)),
        ),
        migrations.AlterField(
            model_name='userseosettings',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 461858)),
        ),
        migrations.AlterField(
            model_name='usersites',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 451512)),
        ),
        migrations.AlterField(
            model_name='usersites',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 451542)),
        ),
        migrations.AlterField(
            model_name='usersitesplan',
            name='createdOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 452275)),
        ),
        migrations.AlterField(
            model_name='usersitesplan',
            name='updatedOn',
            field=models.DateTimeField(blank=True, default=datetime.datetime(2021, 1, 11, 10, 12, 49, 452308)),
        ),
    ]

# Generated by Django 3.1.6 on 2021-02-12 00:49

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DiscordUser',
            fields=[
                ('id', models.BigIntegerField(primary_key=True, serialize=False)),
                ('discord_tag', models.CharField(max_length=100)),
                ('avatar', models.CharField(max_length=100)),
                ('public_flags', models.IntegerField()),
                ('flags', models.IntegerField()),
                ('locale', models.CharField(max_length=100)),
                ('mfa_enabled', models.BooleanField()),
                ('last_login', models.DateTimeField()),
            ],
        ),
    ]

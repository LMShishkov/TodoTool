# Generated by Django 3.1 on 2020-08-15 08:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('action', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='action',
            name='datecompleted',
        ),
        migrations.AddField(
            model_name='action',
            name='dateco_mpleted',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]

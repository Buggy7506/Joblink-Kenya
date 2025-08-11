from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),  # depends on your initial migration
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='skills',
            field=models.CharField(max_length=255, blank=True, null=True),
        ),
    ]

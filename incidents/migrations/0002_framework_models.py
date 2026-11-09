from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='FrameworkControl',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('framework', models.CharField(
                    choices=[
                        ('OWASP_LLM', 'OWASP LLM Top 10'),
                        ('NIST_800_61', 'NIST SP 800-61 Rev 2'),
                        ('HIPAA', 'HIPAA Security Rule'),
                        ('NIST_AI_RMF', 'NIST AI RMF 1.0'),
                    ],
                    db_index=True,
                    max_length=20,
                )),
                ('control_id', models.CharField(max_length=40)),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('requirement', models.TextField()),
                ('remediation', models.TextField()),
                ('attack_categories', models.JSONField(default=list)),
                ('severity_threshold', models.CharField(default='ANY', max_length=20)),
                ('reference_url', models.URLField(blank=True)),
                ('display_badge', models.CharField(blank=True, max_length=60)),
            ],
            options={
                'ordering': ['framework', 'control_id'],
            },
        ),
        migrations.CreateModel(
            name='FrameworkViolation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('analysis', models.TextField()),
                ('matched_patterns', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('incident', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='framework_violations',
                    to='incidents.incident',
                )),
                ('control', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='violations',
                    to='incidents.frameworkcontrol',
                )),
            ],
            options={
                'ordering': ['control__framework', 'control__control_id'],
            },
        ),
        migrations.AddConstraint(
            model_name='frameworkviolation',
            constraint=models.UniqueConstraint(
                fields=['incident', 'control'],
                name='unique_incident_control',
            ),
        ),
    ]

"""
Seeds 700 realistic demo analyst accounts for the login page pool.
Run:  python manage.py seed_demo_users
Reset all suspended:  python manage.py seed_demo_users --reset
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

DEMO_PASSWORD = "Analyst@2024"

FIRST_NAMES = [
    "James", "Sarah", "Marcus", "Priya", "David", "Elena", "Michael", "Aisha",
    "Robert", "Mei", "William", "Fatima", "Daniel", "Sofia", "Christopher",
    "Yuki", "Matthew", "Amara", "Andrew", "Nadia", "Joshua", "Leila", "Ryan",
    "Ingrid", "Kevin", "Zara", "Brian", "Chioma", "Eric", "Hana", "Jason",
    "Isabelle", "Justin", "Layla", "Nathan", "Miriam", "Patrick", "Rania",
    "Samuel", "Thandi", "Thomas", "Valentina", "Tyler", "Xiomara", "Brandon",
    "Yara", "Gregory", "Adaeze", "Derek", "Brianna", "Carlos", "Monique",
    "Diego", "Simone", "Eduardo", "Aaliyah", "Fernando", "Jasmine", "Miguel",
    "Kezia", "Rafael", "Lena", "Andres", "Natasha", "Victor", "Ifeoma",
    "Omar", "Sasha", "Tariq", "Ananya", "Khalid", "Deepa", "Hassan",
    "Sunita", "Ibrahim", "Pita", "Kofi", "Amina", "Kwame", "Abena",
    "Emeka", "Chidi", "Ngozi", "Tunde", "Adaora", "Seun", "Bola",
]

LAST_NAMES = [
    "Chen", "Reid", "Patel", "Wu", "Johnson", "Williams", "Brown", "Jones",
    "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez",
    "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson",
    "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright",
    "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green", "Adams", "Nelson",
    "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
    "Okafor", "Mensah", "Asante", "Diallo", "Traore", "Bakr", "Hassan",
    "Nakamura", "Yamamoto", "Sato", "Tanaka", "Watanabe", "Sharma", "Singh",
    "Kumar", "Gupta", "Shah", "Malik", "Sheikh", "Chaudhry", "Iqbal",
    "Nwosu", "Eze", "Adeyemi", "Balogun", "Obi", "Dike", "Uzoma",
    "Ferreira", "Santos", "Oliveira", "Costa", "Alves", "Pereira", "Carvalho",
]

ROLES = [
    "Senior Security Analyst",
    "Incident Responder",
    "AI Governance Analyst",
    "Compliance Officer",
    "Risk Analyst",
    "Threat Intelligence Analyst",
    "Security Engineer",
    "AI Safety Reviewer",
]

DEPARTMENTS = [
    "cybersecurity",
    "compliance",
    "riskops",
    "aigovernance",
    "security",
    "grc",
    "threatintel",
    "infosec",
]


def generate_accounts(count=700):
    accounts = []
    used = set()
    idx = 0

    while len(accounts) < count:
        first = FIRST_NAMES[idx % len(FIRST_NAMES)]
        last = LAST_NAMES[(idx // len(FIRST_NAMES)) % len(LAST_NAMES)]

        # Disambiguate duplicates with a numeric suffix
        base = f"{first.lower()}.{last.lower()}"
        suffix = ""
        attempt = 0
        while f"{base}{suffix}" in used:
            attempt += 1
            suffix = f"{attempt}"
        username = f"{base}{suffix}"
        used.add(username)

        role = ROLES[idx % len(ROLES)]
        dept = DEPARTMENTS[idx % len(DEPARTMENTS)]
        initials = f"{first[0]}{last[0]}"
        email = f"{username}@{dept}.secureai.io"

        accounts.append({
            "username": username,
            "first_name": first,
            "last_name": last,
            "email": email,
            "role": role,
            "initials": initials,
        })
        idx += 1

    return accounts


DEMO_ACCOUNTS = generate_accounts(700)


class Command(BaseCommand):
    help = "Seed 700 demo analyst accounts for the login page pool"

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Re-activate ALL suspended demo accounts",
        )
        parser.add_argument(
            "--status",
            action="store_true",
            help="Print pool status (active vs suspended) and exit",
        )

    def handle(self, *args, **options):
        if options["status"]:
            usernames = [a["username"] for a in DEMO_ACCOUNTS]
            total = User.objects.filter(username__in=usernames).count()
            active = User.objects.filter(username__in=usernames, is_active=True).count()
            suspended = total - active
            self.stdout.write(f"\nDemo pool status:")
            self.stdout.write(f"  Total   : {total}")
            self.stdout.write(self.style.SUCCESS(f"  Active  : {active}"))
            if suspended:
                self.stdout.write(self.style.ERROR(f"  Suspended: {suspended}"))
            return

        created_count = 0
        updated_count = 0
        reset_count = 0

        for acct in DEMO_ACCOUNTS:
            user, created = User.objects.get_or_create(username=acct["username"])
            user.first_name = acct["first_name"]
            user.last_name = acct["last_name"]
            user.email = acct["email"]
            user.set_password(DEMO_PASSWORD)

            if options["reset"]:
                if not user.is_active:
                    user.is_active = True
                    reset_count += 1
            elif created:
                user.is_active = True

            user.save()

            if created:
                created_count += 1
            else:
                updated_count += 1

        if options["reset"]:
            self.stdout.write(self.style.SUCCESS(
                f"\nReset complete — {reset_count} suspended accounts reactivated."
            ))
        else:
            self.stdout.write(self.style.SUCCESS(
                f"\nSeeded {created_count} new + {updated_count} updated accounts ({len(DEMO_ACCOUNTS)} total)."
            ))

        self.stdout.write(f"Password: {DEMO_PASSWORD}\n")

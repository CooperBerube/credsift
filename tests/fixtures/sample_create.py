import random, hashlib, json

domains   = ["example.com", "corp.com", "target.org", "other.net", "mail.example.com"]
passwords = ["hunter2", "password123", "letmein", "sunshine", "qwerty", "monkey", "correct-horse"]
users     = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "hank"]
sources   = ["rockyou", "linkedin", "adobe", "unknown_paste"]

lines = []
for i in range(1000):
    user   = random.choice(users) + str(random.randint(1, 999))
    domain = random.choice(domains)
    pw     = random.choice(passwords)
    email  = f"{user}@{domain}"
    fmt    = random.randint(0, 4)

    if fmt == 0:
        lines.append(f"{email}:{pw}")
    elif fmt == 1:
        h = hashlib.md5(pw.encode()).hexdigest()
        lines.append(f"{email}:{h}")
    elif fmt == 2:
        h = hashlib.sha1(pw.encode()).hexdigest()
        lines.append(f"{email}:{h}")
    elif fmt == 3:
        lines.append(f"{user}:{pw}")
    elif fmt == 4:
        lines.append(json.dumps({"email": email, "password": pw}))

# Add duplicates to demonstrate dedup
lines += random.choices(lines, k=200)
random.shuffle(lines)

with open("large_dump.txt", "w") as f:
    f.write("\n".join(lines))

print(f"Generated {len(lines)} lines (including ~200 duplicates)")
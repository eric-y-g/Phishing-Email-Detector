import random
import csv
import re
from hashlib import sha256
from pathlib import Path
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
import unicodedata
from collections import Counter, defaultdict
import hashlib



data = Path("Data")
csv.field_size_limit(32 * 1024 * 1024)  # Some bodies exceed the default limit.

metadata_files = ["CEAS_08.csv", "Nazario.csv", "Nigerian_Fraud.csv", "SpamAssasin.csv"]
subject_body_files = ["Enron.csv", "Ling.csv"]
combined_text_files = ["phishing_email.csv"]


split_ratios = {"train": 0.70, "val": 0.15, "test": 0.15}
labels = (0, 1)
min_words = 20
url_pattern = re.compile(r"\b(?:https?://|www\.)[^\s<>]+")
num_pattern = re.compile(r"\d+")
word_pattern = re.compile(r"\w+")

@dataclass(frozen=True)
class Email:
    subject: str
    body: str
    label: int
    source: str

    @property
    def text(self) -> str:
        return "\n\n".join(part for part in (self.subject, self.body) if part)

def normalize(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())

def group_templates(emails: dict[bytes, Email]) -> list[list[Email]]:
    groups = defaultdict(list)
    for key, email in emails.items():
        body = url_pattern.sub(" urlplaceholder ", normalize(email.body))
        words = word_pattern.findall(num_pattern.sub("0", body))
        if len(words) >= min_words:

            template_key = hashlib.sha256(" ".join(words).encode("utf-8")).digest()
            groups[("template", template_key)].append(email)
        else:
            groups[("email", key)].append(email)
    return list(groups.values())


def split_emails(groups, seed):
    rng = random.Random(seed)

    by_label = {0: [], 1: []}
    for group in groups:
        for email in group:
            by_label[email.label].append(email)

    splits = {"train": [], "val": [], "test": []}

    for emails in by_label.values():
        rng.shuffle(emails)

        train_end = int(len(emails) * 0.70)
        val_end = train_end + int(len(emails) * 0.15)

        splits["train"].extend(emails[:train_end])
        splits["val"].extend(emails[train_end:val_end])
        splits["test"].extend(emails[val_end:])

    for emails in splits.values():
        rng.shuffle(emails)

    return splits
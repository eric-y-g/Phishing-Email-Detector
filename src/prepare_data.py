from io import text_encoding
from platform import python_revision
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



data = "Data"
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

def read_csv(filenames):
    """
    Turn csv file into list of rows.
    """
    rows = []

    for filename in filenames:
        full_path = Path(data + "/" + filename)
        with (full_path).open(newline="") as open_file:
            for row in csv.DictReader(open_file, strict=True):
                if None in row or None in row.values():
                    continue

                label = row["label"].strip()

                row["label"] = int(label)
                row["source"] = filename
                rows.append(row)
    return rows

def deduplicate(rows):
    """
    Remove duplicate emails.
    """
    unique = {}
    conflicts = set()

    for row in rows:
        email = Email(row.get("subject", "").stripe(), row.get("text_combined", row.get("body", "")).strip(), row["label"], row["source"],)
        
        text = normalize(email.text)
        if not text:
            continue

        key = sha256(text.encode("utf-8")).digest()
        if key in conflicts:
            continue

        previous = unique.get(key)
        if previous is None:
            unique[key] = (email, row)
        elif previous[0].label != email.label:
            del unique[key]
            conflicts.add(key)

    return unique

def write_output(splits, original_rows):
    output_dir = Path( data + "/" + "prepared" )
    output_dir.mkdir(parents=True, exist_ok=True)

    fields = ["sender", "receiver", "date", "subject", "body", "urls", "text", "label", "source"]

    for name, emails in splits.items():
        filename = output_dir / f"{name}.csv"
        with (filename).open(
            "w", encoding="utf-8", newline="") as open_file:
            writer = csv.DictWriter(open_file, fieldnames=fields)
            writer.writeheader()

            for email in emails:
                row = dict(original_rows[email])
                row["text"] = email.text
                writer.writerow(row)



def main():
    metadata_rows = read_csv(metadata_files)

    unique = deduplicate(metadata_rows)

    emails = {key: email for key, (email, row) in unique.items()}
    original_rows = {email: row for email, row in unique.values()}

    # Your current splitter expects a list of groups.
    splits = split_emails([list(emails.values())], seed=42)

    write_output(splits, original_rows)

    for name, rows in splits.items():
        print(name, len(rows), Counter(email.label for email in rows))
        
if __name__ == "__main__":
    main()
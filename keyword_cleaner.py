import re
import spacy
import logging

logger = logging.getLogger(__name__)

class KeywordCleaner:
    SUFFIXES = ['Inc.', 'Ltd.', 'Co.', 'Corporation', 'LLC',
                'SA', 'S.A', 'GmbH', 'AG', 'S.A.', 'Pvt.', 'PLC', 'Limited']
    KNOWN_BRANDS = ['xiaomi', 'apple', 'microsoft', 'samsung',
                    'huawei', 'lenovo', 'dell', 'hp', 'asus', 'acer']

    def __init__(self):
        self.nlp = spacy.load("en_core_web_sm")

    def clean_vendor_name(self, vendor_name):
        # Remove suffixes
        pattern = re.compile(r'\b(?:' + '|'.join(self.SUFFIXES) + r')\b', re.IGNORECASE)
        vendor_name = pattern.sub('', vendor_name).strip()
        # Remove common patterns like "Inc.", "Ltd.", etc.
        vendor_name = re.sub(r'\b(?:inc|ltd|co|corporation|llc|sa|gmbh|ag|pvt|plc|limited)\b', '', vendor_name, flags=re.IGNORECASE)
        # Remove non-alphanumeric characters except spaces
        cleaned_name = re.sub(r'[^\w\s]', '', vendor_name)
        # Remove extra spaces
        cleaned_name = re.sub(r'\s+', ' ', cleaned_name).strip()
        logger.info("Cleaned vendor name: %s", cleaned_name)
        return cleaned_name

    def extract_keywords(self, cleaned_name):
        doc = self.nlp(cleaned_name)
        keywords = [
            chunk.text.lower() for chunk in doc.noun_chunks if chunk.root.pos_ in [
                'PROPN', 'NOUN']]
        return keywords

    def get_best_keyword(self, keywords, cleaned_name):
        for keyword in keywords:
            for brand in self.KNOWN_BRANDS:
                if brand in keyword:
                    return brand
        best_keyword = keywords[0] if keywords else cleaned_name.split()[0].lower()
        logger.info("Best keyword selected: %s", best_keyword)
        return best_keyword
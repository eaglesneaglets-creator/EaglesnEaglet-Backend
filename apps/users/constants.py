"""
User App Constants

Choices and constants for the users app.
"""

# =============================================================================
# MENTORSHIP TYPE CHOICES (Shared for both Mentors and Mentees)
# =============================================================================
MENTORSHIP_TYPE_CHOICES = [
    ('career_growth', 'Career Growth'),
    ('leadership', 'Leadership Development'),
    ('entrepreneurship', 'Entrepreneurship'),
    ('technology', 'Technology Skills'),
    ('personal_development', 'Personal Development'),
    ('spirituality', 'Spirituality'),
]

# =============================================================================
# MARITAL STATUS CHOICES
# =============================================================================
MARITAL_STATUS_CHOICES = [
    ('single', 'Single'),
    ('married', 'Married'),
    ('divorced', 'Divorced'),
    ('widowed', 'Widowed'),
]

# =============================================================================
# EMPLOYMENT STATUS CHOICES
# =============================================================================
EMPLOYMENT_STATUS_CHOICES = [
    ('employed', 'Employed'),
    ('self_employed', 'Self-Employed'),
    ('student', 'Student'),
    ('unemployed', 'Unemployed'),
]

# =============================================================================
# APPROVAL STATUS CHOICES (For KYC)
# =============================================================================
APPROVAL_STATUS_CHOICES = [
    ('pending', 'Pending Review'),
    ('approved', 'Approved'),
    ('rejected', 'Rejected'),
    ('changes_requested', 'Changes Requested'),
]

# =============================================================================
# LEGACY CHOICES (Kept for backward compatibility)
# =============================================================================
EXPERTISE_CHOICES = [
    ('spiritual_leadership', 'Spiritual Leadership'),
    ('youth_ministry', 'Youth Ministry'),
    ('marriage_counseling', 'Marriage Counseling'),
    ('career_guidance', 'Career Guidance'),
    ('business_mentoring', 'Business & Entrepreneurship'),
    ('education', 'Education & Academic'),
    ('technology', 'Technology & Innovation'),
    ('creative_arts', 'Creative Arts & Media'),
    ('health_wellness', 'Health & Wellness'),
    ('community_service', 'Community Service'),
    ('financial_literacy', 'Financial Literacy'),
    ('personal_development', 'Personal Development'),
]

MENTORSHIP_INTEREST_CHOICES = [
    ('career_advice', 'Career Advice'),
    ('technical_skills', 'Technical Skills'),
    ('leadership', 'Leadership Development'),
    ('interview_prep', 'Interview Preparation'),
    ('salary_negotiation', 'Salary Negotiation'),
    ('spiritual_growth', 'Spiritual Growth'),
    ('life_coaching', 'Life Coaching'),
    ('academic_support', 'Academic Support'),
    ('entrepreneurship', 'Entrepreneurship'),
    ('networking', 'Networking & Connections'),
    ('work_life_balance', 'Work-Life Balance'),
    ('communication_skills', 'Communication Skills'),
]

# =============================================================================
# KYC STATUS CHOICES
# =============================================================================
KYC_STATUS_CHOICES = [
    ('draft', 'Draft'),
    ('submitted', 'Submitted'),
    ('under_review', 'Under Review'),
    ('approved', 'Approved'),
    ('rejected', 'Rejected'),
    ('requires_changes', 'Requires Changes'),
]

# =============================================================================
# FILE UPLOAD SETTINGS
# =============================================================================
MAX_CV_SIZE_MB = 5
MAX_IMAGE_SIZE_MB = 2
ALLOWED_CV_EXTENSIONS = ['pdf', 'docx']
ALLOWED_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'webp']

# Legacy settings (kept for backward compatibility)
MAX_GOVERNMENT_ID_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_RECOMMENDATION_LETTER_SIZE = 10 * 1024 * 1024  # 10 MB
ALLOWED_DOCUMENT_TYPES = ['application/pdf', 'image/jpeg', 'image/png']
ALLOWED_DOCUMENT_EXTENSIONS = ['.pdf', '.jpg', '.jpeg', '.png']

# =============================================================================
# PROFILE DESCRIPTION LIMITS
# =============================================================================
MIN_PROFILE_DESCRIPTION_LENGTH = 100  # characters for mentors
MIN_BIO_LENGTH = 50  # characters for mentees

# Legacy settings
MIN_TESTIMONY_LENGTH = 100  # characters
MAX_TESTIMONY_LENGTH = 2500  # characters (~500 words)

# =============================================================================
# EAGLET (MENTEE) CONSTANTS
# =============================================================================
EDUCATIONAL_LEVEL_CHOICES = [
    ('high_school', 'High School'),
    ('undergraduate', 'Undergraduate'),
    ('graduate', 'Graduate/Postgraduate'),
    ('professional', 'Working Professional'),
    ('other', 'Other'),
]

MENTORSHIP_GOAL_CHOICES = [
    ('career_growth', 'Career Growth'),
    ('skill_development', 'Skill Development'),
    ('spiritual_guidance', 'Spiritual Guidance'),
    ('academic_support', 'Academic Support'),
    ('leadership_training', 'Leadership Training'),
    ('entrepreneurship', 'Starting a Business'),
    ('personal_development', 'Personal Development'),
    ('networking', 'Building Connections'),
]

AGE_GROUP_CHOICES = [
    ('13_17', '13-17 years'),
    ('18_24', '18-24 years'),
    ('25_34', '25-34 years'),
    ('35_44', '35-44 years'),
    ('45_plus', '45+ years'),
]

# =============================================================================
# EMAIL SUBJECTS
# =============================================================================
EMAIL_SUBJECTS = {
    'verification': 'Verify your Eagles & Eaglets account',
    'welcome': 'Welcome to Eagles & Eaglets!',
    'eaglet_welcome': 'Welcome Eaglet! Start Your Mentorship Journey',
    'kyc_submitted': 'Your Mentor Application is Under Review',
    'kyc_approved': 'Congratulations! Your Mentor Application is Approved',
    'kyc_rejected': 'Update Required: Your Mentor Application',
    'kyc_changes_requested': 'Action Required: Update Your Mentor Application',
    'password_reset': 'Reset your Eagles & Eaglets password',
    # New profile emails (for both roles)
    'profile_submitted': 'Your Profile is Under Review',
    'mentor_approved': 'Congratulations! You are now an Eagle Mentor',
    'mentee_approved': 'Welcome! Your Eaglet Profile is Approved',
    'profile_rejected': 'Update Required: Your Profile Application',
    'profile_changes_requested': 'Action Required: Please Update Your Profile',
}

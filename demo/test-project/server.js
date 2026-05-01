const api_key = 'SG_PDPA_DEMO_SECRET_1234567890';

function createProfile(email, nric) {
  return { email, nric, api_key };
}

module.exports = { createProfile };

const Joi = require('joi');

const schema = Joi.object({
  EMAIL_FROM: Joi.string().pattern(/^.*<[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}>$|^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/).default('noreply@example.com'),
});

// Test the current .env value
const testEnv = {
  EMAIL_FROM: "kadArtisan <synapgrid@gmail.com>"
};

const result = schema.validate(testEnv);
console.log('Validation result:', result);
if (result.error) {
  console.error('Validation error:', result.error);
} else {
  console.log('✅ Validation passed!');
}

// Test plain email
const testEnv2 = {
  EMAIL_FROM: "synapgrid@gmail.com"
};
const result2 = schema.validate(testEnv2);
console.log('\nPlain email validation:');
console.log('Validation result:', result2);
if (result2.error) {
  console.error('Validation error:', result2.error);
} else {
  console.log('✅ Plain email validation passed!');
}
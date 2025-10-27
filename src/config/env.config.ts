import "dotenv/config";
import Joi from "joi";

interface ConfigInterface {
  PORT: number;
  KAFKA_BROKER: string;
  JWT_SECRET: string;
}

const envConfigSchema = Joi
  .object({
    PORT: Joi.number().required(),
    KAFKA_BROKER: Joi.string().required(),
    JWT_SECRET: Joi.string().required(),
  })
  .unknown(true);

const validationResult = envConfigSchema.validate(process.env);

if (validationResult.error) {
  const missingVars: string[] = [];
  const invalidVars: string[] = [];

  for (const detail of validationResult.error.details) {
    const varName = detail.path[0] as string;

    if (detail.type === "any.required") {
      missingVars.push(varName);
    } else {
      invalidVars.push(`${varName} (${detail.message})`);
    }
  }

  let errorMessage = "❌ Environment variable configuration error:\n";

  if (missingVars.length > 0) {
    errorMessage += `\n🔴 Missing variables:\n`;
    for (const varName of missingVars) {
      errorMessage += `   - ${varName}\n`;
    }
  }

  if (invalidVars.length > 0) {
    errorMessage += `\n⚠️ Variables with invalid values:\n`;
    for (const varInfo of invalidVars) {
      errorMessage += `   - ${varInfo}\n`;
    }
  }

  errorMessage += `\n💡 Make sure you have an .env file with all the required variables.`;

  throw new Error(errorMessage);
}

const envConfig = validationResult.value as ConfigInterface;

export const EnvsConfig = {
  PORT: envConfig.PORT,
  KAFKA_BROKER: envConfig.KAFKA_BROKER,
  JWT_SECRET: envConfig.JWT_SECRET,
};
import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export const securityRules = {
  "no-eval": "error",
  "no-new-func": "error",
  "no-implied-eval": "error",
  "no-restricted-imports": [
    "error",
    {
      paths: [
        {
          name: "child_process",
          message: "The gateway never runs OS commands"
        },
        {
          name: "node:child_process",
          message: "The gateway never runs OS commands"
        }
      ]
    }
  ],
  "no-restricted-syntax": [
    "error",
    {
      selector:
        "CallExpression[callee.name='createHash'][arguments.0.value=/^(md5|sha-?1)$/i]",
      message: "MD5 and SHA-1 are disallowed (ASVS V11.4.1)."
    },
    {
      selector:
        "CallExpression[callee.property.name='createHash'][arguments.0.value=/^(md5|sha-?1)$/i]",
      message: "MD5 and SHA-1 are disallowed (ASVS V11.4.1)."
    }
  ]
  // Where mcpgw-003 and mcpgw-005 add rules: add database and HTML/OAuth lint rules here.
};

export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**", "eslint.config.js"]
  },
  eslint.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      ...securityRules,
      "@typescript-eslint/no-implied-eval": "error"
    }
  }
);

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

const childProcessRestrictedPaths = [
  {
    name: "child_process",
    message: "The gateway never runs OS commands"
  },
  {
    name: "node:child_process",
    message: "The gateway never runs OS commands"
  }
];

export const securityRules = {
  "no-eval": "error",
  "no-new-func": "error",
  "no-implied-eval": "error",
  "no-restricted-imports": [
    "error",
    {
      paths: childProcessRestrictedPaths
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
    },
    {
      selector:
        "CallExpression[callee.property.name=/^(prepare|exec|pragma|run|get|all)$/] > TemplateLiteral[expressions.length>0]",
      message: "Use parameterised SQL with bound parameters instead of template interpolation (ASVS V1.2.4)."
    },
    {
      selector:
        "CallExpression[callee.property.name=/^(prepare|exec|pragma|run|get|all)$/] > BinaryExpression",
      message: "Use parameterised SQL with bound parameters instead of string concatenation (ASVS V1.2.4)."
    }
  ]
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
  },
  {
    files: ["src/public/**/*.ts", "src/oauth/**/*.ts", "src/mcp/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: childProcessRestrictedPaths,
          patterns: [
            {
              regex: "(^|/)approve(/|$)",
              message: "Public, OAuth and MCP modules must not import from src/approve."
            }
          ]
        }
      ]
    }
  },
  {
    files: ["src/approve/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: childProcessRestrictedPaths,
          patterns: [
            {
              regex: "(^|/)public(/|$)",
              message: "Approve modules must not import from src/public."
            }
          ]
        }
      ]
    }
  }
);

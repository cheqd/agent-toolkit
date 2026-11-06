// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';
import globals from 'globals';

export default tseslint.config(
	{
		ignores: ['**/dist/**', '**/node_modules/**', '**/*.tsbuildinfo'],
	},
	eslint.configs.recommended,
	...tseslint.configs.recommended,
	eslintConfigPrettier,
	{
		languageOptions: {
			globals: globals.node,
		},
		rules: {
			// Fail-closed helpers (e.g. retrieve-public-key.ts's `fail(): never`) and deliberately
			// faithful upstream ports (e.g. ap2's dead-but-documented `agent_recurrence` fields)
			// read naturally with a leading underscore or an explicit `void` discard - don't fight that.
			'@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
			'no-console': 'warn',
		},
	},
	{
		files: ['**/test/*.test.mjs', '**/smoke-test*.mjs', '**/sample/**/*.mjs', '**/conformance/**/*.mjs'],
		rules: {
			'no-console': 'off',
		},
	},
);

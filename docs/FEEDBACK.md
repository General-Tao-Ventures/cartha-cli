# Feedback Guide

This guide explains how to provide feedback on the Cartha CLI.

## Providing Feedback

We value your feedback! There are several ways to share your thoughts:

### 1. Discord

Join our official Discord channels for real-time feedback and discussions:

- **Cartha Subnet Channel**: Share feedback in #cartha-sn35: https://discord.gg/X9YzEbRe
- **Bittensor Channel**: Reach out directly to Cartha/0xMarkets team members: https://discord.com/channels/799672011265015819/1415790978077556906

### 2. GitHub Issues

Use GitHub Issues to report bugs, request features, or provide testnet feedback:

- **Bug Reports** - Report bugs or unexpected behavior in the CLI
- **Feature Requests** - Suggest new features or enhancements
- **Testnet Feedback** - Share your testnet CLI experience

### 3. Pull Requests

Contribute code improvements:

- Fix bugs
- Add features
- Improve documentation
- Enhance tests

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

### 4. Discussions

Use GitHub Discussions for:

- Questions and answers about using the CLI
- General discussions about CLI features
- Community ideas and suggestions

## Feedback Categories

### Bug Reports

When reporting a bug, please include:

- **Clear description** of what went wrong
- **Steps to reproduce** the issue
- **Expected vs actual** behavior
- **Environment** information:
  - OS and version
  - Python version
  - `uv` version (if using)
  - Bittensor network (testnet/mainnet)
  - NetUID
- **Command used** - The exact command that failed
- **Error messages** - Full error output
- **Wallet information** - Wallet name and hotkey (redact sensitive parts)

### Feature Requests

When requesting a feature, please include:

- **Problem statement** - What problem does this solve?
- **Proposed solution** - How should it work?
- **Use cases** - Specific examples of how miners would use it
- **Priority** - How important is this to you?

### Testnet Feedback

When providing testnet feedback, please include:

- **What you tested** - Which CLI commands did you try?
- **What worked well** - What went smoothly?
- **Issues encountered** - What problems did you face?
- **Suggestions** - How can we improve the CLI experience?
- **Workflow feedback** - Was the registration/proof process clear?

## CLI-Specific Feedback

### Registration Issues

If you encounter registration problems:

- Include the exact command used
- Share error messages
- Note wallet and hotkey names (redact sensitive parts)
- Include network and netuid

### Lock Proof Issues

If you have problems with lock proofs:

- Include the `build_lock_proof.py` output (redact sensitive data)
- Share the `prove-lock` command used
- Include error messages from the verifier
- Note if using testnet or mainnet

### Pair Password Issues

If you encounter pair password problems:

- Include the `pair status` command output
- Share any error messages
- Note if you're registering or retrieving a password
- Include network and netuid

### UX/Usability Feedback

For user experience feedback:

- Describe what was confusing
- Suggest clearer error messages
- Propose better command names or options
- Share ideas for improved workflows

## Feedback Best Practices

### Be Specific

- Provide concrete examples
- Include relevant command outputs
- Describe the exact steps you took
- Include command-line arguments used

### Be Constructive

- Focus on the issue, not the person
- Suggest solutions when possible
- Explain the impact of the issue
- Consider security implications

### Be Patient

- Give maintainers time to respond
- Follow up if needed, but be respectful
- Understand that fixes take time
- Remember this is open-source software

## Security Considerations

When reporting issues:

- **Never** share private keys or mnemonics
- **Never** share pair passwords
- Redact sensitive information from logs
- Use testnet for testing when possible

## Response Times

We aim to respond to:

- **Critical bugs** (CLI crashes, security issues): Within 24 hours
- **General issues**: Within 3-5 business days
- **Feature requests**: Within 1-2 weeks
- **Pull requests**: Within 1 week

## Getting Help

If you need help:

1. Check the [README](../README.md) and [testnet guide](../testnet/README.md)
2. Review command help: `uv run cartha --help`
3. Search existing issues
4. Ask in discussions
5. Open an issue with your question

## Security Issues

For security-related issues, please:

- **Do NOT** open a public issue
- Email security concerns directly to maintainers
- Include detailed information about the vulnerability
- Allow time for a fix before disclosure

## Thank You

Your feedback helps make the Cartha CLI better. We appreciate your time and effort! 🎉


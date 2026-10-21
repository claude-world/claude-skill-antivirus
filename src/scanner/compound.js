const LEVELS = ['critical', 'high', 'medium', 'low', 'info'];
const emptyFindings = () => ({ critical: [], high: [], medium: [], low: [], info: [] });

/**
 * Run a compound-behavior check ("signal A and signal B appear together") per file.
 *
 * These heuristics were written when only SKILL.md was scanned. Now that a skill's
 * whole directory is scanned (#33), signals scattered across unrelated files are
 * much weaker evidence than the same signals inside one script, so each file is
 * judged on its own at the original severity. A match that only appears when all
 * files are combined is still reported, at MEDIUM and marked "(across files)", so
 * no signal is dropped.
 */
export function checkCompoundPerFile(skillContent, check, findings) {
  const units = [skillContent.rawContent || '', ...(skillContent.files || []).map((f) => f.content)];
  const seen = new Set();

  for (const unit of units) {
    const perFile = emptyFindings();
    check(unit, perFile);
    for (const level of LEVELS) {
      for (const finding of perFile[level]) {
        if (seen.has(finding.title)) continue;
        seen.add(finding.title);
        findings[level].push(finding);
      }
    }
  }

  const combined = emptyFindings();
  check(units.join('\n'), combined);
  for (const level of LEVELS) {
    for (const finding of combined[level]) {
      if (seen.has(finding.title)) continue;
      seen.add(finding.title);
      const downgraded = level === 'critical' || level === 'high' ? 'medium' : level;
      findings[downgraded].push({
        ...finding,
        title: `${finding.title} (across files)`,
        description: `${finding.description}. The signals are spread across different files rather than appearing in one script.`,
      });
    }
  }
}

library validation.constraint;

// TODO: this should be moved into a separate validate project

/**
 * Represents a constraint that was violated.
 * 
 * _Note: it is likely that there will be more structure added in the future
 * similar to that in the Java Bean Validation api
 */
class ConstraintViolation {
  final String message;

  ConstraintViolation(this.message);

  @override
  String toString() => message;
}

class ConstraintViolations {
  final String preamble;
  final Set<ConstraintViolation> violations;

  // TODO: likely too simplistic
  String get summaryMessage =>
      '$preamble. The following constraints were violated\n'
      '${violations.join("\n")}';

  ConstraintViolations(this.preamble, this.violations);
}

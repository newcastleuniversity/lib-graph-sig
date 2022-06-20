package uk.ac.ncl.cascade;

import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import java.lang.reflect.AnnotatedElement;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;
import org.junit.platform.commons.util.AnnotationUtils;

class EnabledOnSuiteCondition implements ExecutionCondition, TestExecutionExceptionHandler {
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private static final ConditionEvaluationResult DISABLED_BY_DEFAULT =
      ConditionEvaluationResult.disabled("Disabled suite is not present");
  private static final ConditionEvaluationResult ENABLED_BY_DEFAULT =
      ConditionEvaluationResult.enabled("@EnabledOnSuite is not present");
  static final ConditionEvaluationResult ENABLED_ON_CURRENT_SUITE =
      ConditionEvaluationResult.enabled("Enabled on suite: ");
  static final ConditionEvaluationResult DISABLED_ON_CURRENT_SUITE =
      ConditionEvaluationResult.disabled("Disabled on suite: ");

  EnabledOnSuiteCondition() {}

  public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
    Optional<EnabledOnSuite> optional =
        AnnotationUtils.findAnnotation(context.getElement(), EnabledOnSuite.class);

    Optional<AnnotatedElement> contextElement = context.getElement();
    AnnotatedElement annotatedElement = contextElement.orElse(null);

    if (annotatedElement == null) return null;

    if (optional.isPresent()) {
      GSSuite gsSuite = ((EnabledOnSuite) optional.get()).name();
      //      Preconditions.condition(
      //          gsSuite == null, "You must declare at least one suite name in @EnabledOnSuite");
      String actual = System.getProperty("GSSuite");

      if (GSSuite.suiteExists(actual)) {
        return ENABLED_ON_CURRENT_SUITE;
      } else {
        return DISABLED_ON_CURRENT_SUITE;
      }
    } else {
      return DISABLED_BY_DEFAULT;
    }
  }

  @Override
  public void handleTestExecutionException(ExtensionContext context, Throwable throwable)
      throws  TestSuiteFailedException {
    gslog.log(Level.SEVERE, "test exception in " + context.getRequiredTestClass().getName());
    throwable.printStackTrace(); // display error stack trace for debugging
    gslog.severe("terminate test");
    throw new TestSuiteFailedException("failed test", throwable);
  }
}

package eu.prismacloud.primitives.zkpgs;

import java.lang.reflect.AnnotatedElement;
import java.util.Optional;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.util.AnnotationUtils;

class EnabledOnSuiteCondition implements ExecutionCondition {

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
}

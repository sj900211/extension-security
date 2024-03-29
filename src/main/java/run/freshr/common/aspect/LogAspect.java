package run.freshr.common.aspect;

import static java.util.Optional.ofNullable;
import static run.freshr.common.security.TokenProvider.signedId;
import static run.freshr.common.security.TokenProvider.signedRole;
import static run.freshr.domain.auth.enumerations.Role.ROLE_ANONYMOUS;

import java.util.Comparator;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

/**
 * 전역 로깅 설정
 *
 * @author FreshR
 * @apiNote 전역 로깅 설정
 * @since 2024. 3. 29. 오전 11:08:41
 */
@Slf4j
@Aspect
@Component
public class LogAspect {

  /**
   * Controller 로깅 설정
   *
   * @param proceedingJoinPoint AOP 대상에 대한 정보
   * @return object
   * @throws Throwable throwable
   * @apiNote Controller 로깅 설정
   * @author FreshR
   * @since 2024. 3. 29. 오전 11:08:41
   */
  @Around("execution(* *.*.controller..*.*(..))")
  public Object controllerLogging(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
    String className = proceedingJoinPoint.getSignature().getDeclaringTypeName();
    String methodName = proceedingJoinPoint.getSignature().getName();
    String proceedName = className + "." + methodName;
    String roleName = ofNullable(signedRole.get()).orElse(ROLE_ANONYMOUS).getKey();
    String signedIdName = ofNullable(signedId.get()).orElse("");
    int max = Stream.of(proceedName, roleName, signedIdName)
        .map(String::length)
        .max(Comparator.comparing(item -> item))
        .orElse(0);
    String outline = "-".repeat(max);
    String proceedPadding = String.format("%-" + max + "s", proceedName);
    String rolePadding = String.format("%-" + max + "s", roleName);
    String signedIdPadding = String.format("%-" + max + "s", signedIdName);

    log.debug("""
        +---------+-{}-+
        | PROCEED | {} |
        | ROLE    | {} |
        | ID      | {} |
        +---------+-{}-+
        """, outline, proceedPadding, rolePadding, signedIdPadding, outline);

    return proceedingJoinPoint.proceed();
  }

}

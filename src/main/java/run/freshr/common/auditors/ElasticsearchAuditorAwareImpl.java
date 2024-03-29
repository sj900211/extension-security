package run.freshr.common.auditors;

import static org.springframework.util.StringUtils.hasLength;

import jakarta.annotation.Nonnull;
import java.util.Optional;
import org.springframework.data.domain.AuditorAware;
import org.springframework.stereotype.Component;
import run.freshr.common.security.TokenProvider;
import run.freshr.common.utils.RestUtilSecurityAware;
import run.freshr.domain.account.entity.Account;

/**
 * Elasticsearch Auditing 구현체
 *
 * @author FreshR
 * @apiNote Elasticsearch Auditing 구현체<br>
 *          데이터 변동이 발생했을 경우 주체가 되는 계정 정보를 조회하는 로직을 작성
 * @since 2024. 3. 29. 오전 11:04:53
 */
@Component
public class ElasticsearchAuditorAwareImpl implements AuditorAware<Account> {

  /**
   * 요청한 계정 정보 조회
   *
   * @return current auditor
   * @apiNote 요청한 계정 정보 조회
   * @author FreshR
   * @since 2024. 3. 29. 오전 11:04:53
   */
  @Nonnull
  @Override
  public Optional<Account> getCurrentAuditor() {
    String signedId = TokenProvider.signedId.get();
    Account signed = null;

    if (hasLength(signedId)) {
      signed = RestUtilSecurityAware.getSigned();
    }

    return Optional.ofNullable(signed);
  }

}

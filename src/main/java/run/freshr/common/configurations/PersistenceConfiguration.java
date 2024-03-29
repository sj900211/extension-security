package run.freshr.common.configurations;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.elasticsearch.config.EnableElasticsearchAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import run.freshr.common.auditors.AuditorAwareImpl;
import run.freshr.common.auditors.ElasticsearchAuditorAwareImpl;
import run.freshr.domain.account.entity.Account;

/**
 * JPA Auditing 설정
 *
 * @author FreshR
 * @apiNote JPA Auditing 설정
 * @since 2024. 3. 29. 오전 10:58:35
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef="auditorProvider")
@EnableElasticsearchAuditing(auditorAwareRef="elasticsearchAuditorProvider")
public class PersistenceConfiguration {

  @Bean
  public AuditorAware<Account> auditorProvider() {
    return new AuditorAwareImpl();
  }

  @Bean
  public AuditorAware<Account> elasticsearchAuditorProvider() {
    return new ElasticsearchAuditorAwareImpl();
  }

}

package com.patternknife.securityhelper.oauth2.config.queue.pool;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

import java.util.concurrent.ThreadPoolExecutor;

@EnableAsync
@Configuration
@EnableScheduling
public class ThreadPoolConfig {
    @Bean
    public ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();

        // 스케쥴러 스레드풀의 사이즈. 여기서는 머신의 프로세서 수로 하였다.
        // Runtime.getRuntime().availableProcessors()
        taskScheduler.setPoolSize(3);

        // 로그에 찍힐 스케쥴러 스레드의 접두사
        taskScheduler.setThreadNamePrefix("Scheduler-Thread-");

        // 모든 설정을 적용하고 ThreadPoolTaskScheduler를 초기화
        taskScheduler.initialize();

        return taskScheduler;
    }

    @Bean
    public ThreadPoolTaskExecutor threadPoolTaskExecutor() {
        ThreadPoolTaskExecutor taskExecutor = new ThreadPoolTaskExecutor();

        // 로그에 찍힐 스레드의 접두사
        taskExecutor.setThreadNamePrefix("Async-Thread-");

        // 기본적으로 유지할 스레드풀의 사이즈. 설정값은 머신의 프로세서 수로 하였다.
        taskExecutor.setCorePoolSize(3);

        // 최대 스레드풀 사이즈
        taskExecutor.setMaxPoolSize(5);

        // 최대 스레드풀 사이즈만큼 스레드가 생성되면 생성을 대기시킬 스레드의 수
        taskExecutor.setQueueCapacity(50);

        // MaxPoolSize와 QueueCapacity이상으로 스레드가 생성되야 할 경우의 정책
        // CallerRunsPolicy는 스레드를 생성하고 처리를 위임하려고 한 스레드가 직접 모든 처리를 다하도록 하는 정책
        taskExecutor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

        // 어플리케이션 종료시 동작중이던 스레드가 모든 처리를 완료할때까지 대기한 후 종료한다
        taskExecutor.setWaitForTasksToCompleteOnShutdown(true);

        // CorePool 스레드의 유휴시간(기본 60s)이 지나면 kill할지 여부.
        // 기본값은 false이며, true로 설정하면 스레드를 kill한다.
        taskExecutor.setAllowCoreThreadTimeOut(false);

        // 모든 설정을 적용하고 ThreadPoolTaskExecutor를 초기화
        taskExecutor.initialize();

        return taskExecutor;
    }
}

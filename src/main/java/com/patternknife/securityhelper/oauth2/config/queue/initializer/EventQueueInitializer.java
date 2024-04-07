package com.patternknife.securityhelper.oauth2.config.queue.initializer;

import com.patternknife.securityhelper.oauth2.domain.exceldbwritetask.queue.ExcelDBWriteTaskEventQueue;
import com.patternknife.securityhelper.oauth2.domain.exceldbreadtask.queue.ExcelDBReadInMemoryData;
import com.patternknife.securityhelper.oauth2.domain.exceldbreadtask.queue.ExcelDBReadTaskEventQueue;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class EventQueueInitializer {
    @Bean
    public ExcelDBWriteTaskEventQueue transactionClinicEventQueue() {
        return ExcelDBWriteTaskEventQueue.of(1_000);
    }

    @Bean
    public ExcelDBReadTaskEventQueue transactionDBReadEventQueue() {
        /*
         *   이 코드는 이벤트 큐(ExcelDBReadTaskEventQueue)의 용량(capacity)을 설정하는 것입니다.
         *   여기서 1_000은 이벤트 큐에 저장될 수 있는 최대 이벤트 수를 나타냅니다. 따라서 이벤트 큐의 용량이 결정되면,
         *   해당 큐에 새로운 이벤트가 발생할 때마다 큐에 추가되며, 용량이 넘어가면 새로운 이벤트는 추가되지 않습니다.
         * */
        return ExcelDBReadTaskEventQueue.of(1_000);
    }
    @Bean
    public ExcelDBReadInMemoryData excelDBReadTaskData() {
        return ExcelDBReadInMemoryData.of();
    }
}

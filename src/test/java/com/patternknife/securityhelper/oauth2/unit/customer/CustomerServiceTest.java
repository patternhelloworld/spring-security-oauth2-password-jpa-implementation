package com.patternknife.securityhelper.oauth2.unit.customer;

import com.patternknife.securityhelper.oauth2.config.security.principal.AccessTokenUserInfo;
import com.patternknife.securityhelper.oauth2.domain.customer.dao.CustomerRepository;
import com.patternknife.securityhelper.oauth2.domain.customer.service.CustomerService;
import com.patternknife.securityhelper.oauth2.domain.role.entity.Role;
import com.patternknife.securityhelper.oauth2.util.auth.MockAuth;
import com.patternknife.securityhelper.oauth2.util.auth.UnitMockAuth;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.jpa.repository.support.Querydsl;
import org.springframework.test.context.event.annotation.BeforeTestMethod;
import org.springframework.web.context.WebApplicationContext;

import java.util.HashSet;
import java.util.Set;


@ExtendWith(MockitoExtension.class)
@DataJpaTest
public class CustomerServiceTest {


    @InjectMocks
    private CustomerService customerService;

    @Mock
    private CustomerRepository customerRepository;

    private AccessTokenUserInfo accessTokenUserInfo;

    @Autowired
    protected WebApplicationContext context;

    private MockAuth mockAuth;

    @BeforeTestMethod
    public void beforeMethod() {
    }

    @BeforeEach
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        // 기본 권한만 부여된 사용자로 시작한다.
        mockAuth = new UnitMockAuth();
        Set<Role> roles = new HashSet<>();
        Role role = Role.builder().id(1L).name("CUSTOMER").build();
        roles.add(role);

        // putAuthenticationPrincipal 에 Inject
        accessTokenUserInfo = mockAuth.mockAuthenticationPrincipal(mockAuth.mockCustomerObject());

    }

    @Mock
    private JPAQueryFactory jpaQueryFactory;

    @Mock
    protected Querydsl getQuerydsl;

/*    @Test
    public void findCustomersByPageRequest_성공() throws Exception {

*//*        //given
        List<Customer> customerList = new ArrayList<Customer>();
        customerList.add(mockAuth.mockUserObject(null));
        customerList.add(mockAuth.mockUserObject(null));
        customerList.add(mockAuth.mockUserObject(null));

        Boolean skipPagination = false;
        Integer pageNum = 1;
        Integer pageSize = 5;

        // Mock the behavior of queryFactory
        final QCustomer qCustomer = QCustomer.customer;
        when(jpaQueryFactory.selectFrom(any())).thenReturn(any());

        Sort.Direction sortDirection = Sort.Direction.DESC;
        String sortedColumn = "updated_at";

        // Pagination
        if (skipPagination) {
            pageNum = Integer.parseInt(CommonConstant.COMMON_PAGE_NUM);
            pageSize = Integer.parseInt(CommonConstant.COMMON_PAGE_SIZE_DEFAULT_MAX);
        }
        PageRequest pageRequest = PageRequest.of(pageNum - 1, pageSize, Sort.by(sortDirection, sortedColumn));
        given(getQuerydsl.applyPagination(pageRequest,any())).willReturn((JPQLQuery<Object>) customerList);


        //then
        Page<Customer> result = customerService.findCustomersByPageRequest(false, 1, 5, "", "", accessTokenUserInfo);


        assertThat(customerList.get(0).getEmail().equals("cicd@test.com")).isEqualTo(result.getContent().get(0).getEmail().equals("cicd@test.com"));*//*

    }*/

/*    @Test(expected = JsonProcessingException.class)
    public void findCustomersByPageRequest_customerSearchFilter_예외_발생() throws JsonProcessingException {

        // given

        // when
        Page<Customer> page1 = customerService.findCustomersByPageRequest(false, 1, 5, "{aaa}", "", accessTokenUserInfo);

        // then
    }*/

/*
    @Test
    public void create_사용자_등록_성공() {
        //given
        final Customer dto = new Customer();

        given(customerRepository.save(any(Customer.class))).willReturn(dto);

        //when
        final Customer customer = customerService.createCustomer(dto);

        //then
        verify(customerRepository, atLeastOnce()).save(any(Customer.class));
        assertThat(dto).isEqualTo(customer);

    }
*/




}
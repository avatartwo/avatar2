
#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu-common.h"
#include "qapi/qapi-commands-avatar.h"
#include "qapi/error.h"

#include "hw/sysbus.h"
#include "sysemu/sysemu.h"

#ifdef TARGET_ARM
#include "target/arm/cpu.h"

#if !defined(TARGET_AARCH64)
#endif

#elif defined(TARGET_MIPS)
#include "target/mips/cpu.h"
#endif

#include "hw/avatar/interrupts.h"
#include "hw/avatar/avatar_posix.h"
#include "hw/avatar/remote_memory.h"


extern  QemuAvatarMessageQueue *rmem_rx_queue_ref;
extern  QemuAvatarMessageQueue *rmem_tx_queue_ref;

#if defined(TARGET_ARM)

static QemuAvatarMessageQueue *irq_rx_queue_ref = NULL;
static QemuAvatarMessageQueue *irq_tx_queue_ref = NULL;

static uint64_t req_id;
static uint8_t ignore_irq_return_map[32] = {0};
#endif

/* Architecture specific declaration */
#if defined(TARGET_ARM)
static bool armv7m_exception_handling_enabled = false;


void qmp_avatar_armv7m_set_vector_table_base(int64_t num_cpu, int64_t base, Error **errp)
{
//#ifdef TARGET_ARM
    qemu_log_mask(LOG_AVATAR, "Changing NVIC base to%lx\n", base & 0xffffff80);
    ARMCPU *armcpu = ARM_CPU(qemu_get_cpu(num_cpu));
    /* MM: qemu now has multiple vecbases, we may need to fix this */
    armcpu->env.v7m.vecbase[armcpu->env.v7m.secure] = base & 0xffffff80;
//#endif
}


void avatar_armv7m_nvic_forward_write(uint32_t offset, uint32_t value, unsigned size){
    int ret;
    RemoteMemoryResp resp;

    qemu_log_mask(LOG_AVATAR, "armv7m nvic write at offset 0x%x\n", offset);
    qemu_log_flush();
    if(!armv7m_exception_handling_enabled){
        return;
    }

    memset(&resp, 0, sizeof(resp));

    uint64_t pc = get_current_pc();
    
    //for now, assusme nvic at the standard location at 0xE000E000
    MemoryForwardReq request = {req_id++, pc, 0xe000e000+offset, value, size, AVATAR_WRITE};

    qemu_avatar_mq_send(rmem_tx_queue_ref, &request, sizeof(request));
    ret = qemu_avatar_mq_receive(rmem_rx_queue_ref, &resp, sizeof(resp));
    if(!resp.success || (resp.id != request.id)){

        error_report("RemoteMemoryWrite for NVIC failed (%d)!\n", ret);
        exit(1);
    }
}

void qmp_avatar_armv7m_enable_irq(const char *irq_rx_queue_name,
                                  const char *irq_tx_queue_name, 
                                  const char *rmem_rx_queue_name,
                                  const char *rmem_tx_queue_name, Error **errp)
{
    if(irq_rx_queue_ref == NULL){
        irq_rx_queue_ref = malloc(sizeof(QemuAvatarMessageQueue));
        qemu_avatar_mq_open_read(irq_rx_queue_ref, irq_rx_queue_name,
                sizeof(V7MInterruptResp));
    }
    if(irq_tx_queue_ref == NULL){
        irq_tx_queue_ref = malloc(sizeof(QemuAvatarMessageQueue));
        qemu_avatar_mq_open_write(irq_tx_queue_ref, irq_tx_queue_name,
                sizeof(V7MInterruptReq));
    }

    if(rmem_rx_queue_ref == NULL){
        rmem_rx_queue_ref = malloc(sizeof(QemuAvatarMessageQueue));
        qemu_avatar_mq_open_read(rmem_rx_queue_ref, rmem_rx_queue_name, sizeof(RemoteMemoryResp));
    }
    if(rmem_tx_queue_ref == NULL){
        rmem_tx_queue_ref = malloc(sizeof(QemuAvatarMessageQueue));
        qemu_avatar_mq_open_write(rmem_tx_queue_ref, rmem_tx_queue_name, sizeof(MemoryForwardReq));
    }

    armv7m_exception_handling_enabled = true;
    qemu_log_mask(LOG_AVATAR, "armv7m interrupt injection enabled\n");
    qemu_log_flush();
}


void qmp_avatar_armv7m_disable_irq(Error **errp)
{
    qemu_log_mask(LOG_AVATAR, "armv7m interrupt injection disabled\n");
    armv7m_exception_handling_enabled = false;
    qemu_log_flush();
}


void qmp_avatar_armv7m_ignore_irq_return(int64_t num_irq, Error **errp)
{
    ignore_irq_return_map[num_irq/8] |= 1 << num_irq % 8;
}

void qmp_avatar_armv7m_unignore_irq_return(int64_t num_irq, Error **errp)
{
    ignore_irq_return_map[num_irq/8] &= 0 << num_irq % 8;
}

void qmp_avatar_armv7m_inject_irq(int64_t num_cpu,int64_t num_irq, Error **errp)
{
//#ifdef TARGET_ARM
    qemu_log_mask(LOG_AVATAR, "Injecting exception 0x%lx\n", num_irq);
    ARMCPU *armcpu = ARM_CPU(qemu_get_cpu(num_cpu));
    CPUARMState *env = &armcpu->env;
    /*  MM: for now, we can only inject non-secure irqs */
    armv7m_nvic_set_pending(env->nvic, num_irq, false);
//#endif
}


void avatar_armv7m_exception_exit(int irq, uint32_t type)
{
    int ret;
    V7MInterruptResp resp;
    V7MInterruptReq request = {req_id++, irq, INTERRUPT_EXIT, type};

    if( (ignore_irq_return_map[irq/8] & 1 << irq % 8) || !armv7m_exception_handling_enabled)
    {
        qemu_log_mask(LOG_AVATAR, "Returning form 0x%x - Ignored by avatar\n", irq);
    }
    else{
        qemu_log_mask(LOG_AVATAR, "Returning form 0x%x\n", irq);
        memset(&resp, 0, sizeof(resp));

        qemu_avatar_mq_send(irq_tx_queue_ref, &request, sizeof(request));
        ret = qemu_avatar_mq_receive(irq_rx_queue_ref, &resp, sizeof(resp));

        if(!resp.success || (resp.id != request.id) || (resp.operation != INTERRUPT_EXIT) ){
            error_report("ARMv7mInterruptRequest failed (%d)!\n", ret);
            exit(1);
        }
    }
}

void avatar_armv7m_exception_enter(int irq)
{
    int ret;
    V7MInterruptResp resp;
    V7MInterruptReq request = {req_id++, irq, INTERRUPT_ENTER, 0};

    if( (ignore_irq_return_map[irq/8] & 1 << irq % 8) || !armv7m_exception_handling_enabled)
    {
        qemu_log_mask(LOG_AVATAR, "Entered IRQ 0x%x - Ignored by avatar\n", irq);
    }
    else{
        qemu_log_mask(LOG_AVATAR, "Entering IRQ 0x%x\n", irq);
        memset(&resp, 0, sizeof(resp));

        qemu_avatar_mq_send(irq_tx_queue_ref, &request, sizeof(request));
        ret = qemu_avatar_mq_receive(irq_rx_queue_ref, &resp, sizeof(resp));

        if(!resp.success || (resp.id != request.id) || (resp.operation != INTERRUPT_ENTER)){
            error_report("ARMv7mInterruptRequest failed (%d)!\n", ret);
            exit(1);
        }
    }
}
#endif  /* defined(TARGET_ARM) && !defined(TARGET_AARCH64) */

/* M19 R4: proof that the GPU executes work, without X. It loads the Vulkan loader the tree ships, picks
 * the one Adreno that Turnip offers, seeds a 16 MiB host-visible buffer from the CPU, has the GPU fill it,
 * and checks every word on the CPU. A CPU device is refused unless --allow-cpu is given, which only the
 * offline tests use, on lavapipe.
 *
 * (R4m) dmabuf H: Turnip's own import of a dma-buf from heap H, whose code is not freedreno's. The buffer is
 * imported, then written by the CPU, then copied by the GPU into host memory and counted; then the same buffer is
 * imported a second time and copied, and the first import copied once more. Each count is the share of words
 * holding the CPU's word, in thousandths.
 *
 * Nothing here touches KMS or X. Vulkan's own headers are needed to build it; the loader is opened at run
 * time, so the binary needs only the C library. */
#define _GNU_SOURCE
#define VK_NO_PROTOTYPES
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

#define FILL_BYTES (16u << 20)
#define FILL_WORD 0x4d313921u /* "!91M" in memory, "M19!" read as a word */
#define SEED_BYTE 0xa5
#define WAIT_NS 10000000000ull
#define ADRENO_VENDOR 0x5143u
#define MAX_DEVICES 8u

static PFN_vkGetInstanceProcAddr gipa;
static VkInstance instance = VK_NULL_HANDLE;

#define LOAD(name) PFN_##name name = (PFN_##name)gipa(instance, #name)

static unsigned long long now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000ull + (unsigned long long)t.tv_nsec / 1000ull;
}

static int fail(const char *what, VkResult result)
{
    printf("M19 GPU vulkan FAIL %s result=%d\n", what, (int)result);
    return 1;
}

/* (R4m) The dma-buf the CPU writes after Turnip imported it. */
#define LATE_BYTES (256u * 256u * 4u)
#define LATE_WORD 0x4d313922u
struct m19_heap_alloc { uint64_t len; uint32_t fd, fd_flags; uint64_t heap_flags; };
struct m19_dmabuf_sync { uint64_t flags; };
#define M19_HEAP_ALLOC _IOWR('H', 0x0, struct m19_heap_alloc)
#define M19_DMABUF_SYNC _IOW('b', 0, struct m19_dmabuf_sync)

struct late {
    VkPhysicalDevice chosen;
    VkDevice device;
    VkQueue queue;
    VkCommandPool pool;
    VkBuffer host;
    VkDeviceMemory host_memory;
    uint32_t *mapped;
    int coherent;
};

static long share_of(const uint32_t *words)
{
    uint32_t hits = 0;
    for (uint32_t i = 0; i < LATE_BYTES / 4u; i++)
        hits += words[i] == LATE_WORD;
    return (long)((uint64_t)hits * 1000u / (LATE_BYTES / 4u));
}

/* fd imported as a transfer source: a buffer bound to memory Vulkan made from a duplicate of it. */
static VkResult import_dmabuf(struct late *l, int fd, VkBuffer *buffer, VkDeviceMemory *memory)
{
    LOAD(vkGetDeviceProcAddr);
    LOAD(vkCreateBuffer);
    LOAD(vkGetBufferMemoryRequirements);
    LOAD(vkAllocateMemory);
    LOAD(vkBindBufferMemory);
    PFN_vkGetMemoryFdPropertiesKHR fd_properties = (PFN_vkGetMemoryFdPropertiesKHR)vkGetDeviceProcAddr(l->device, "vkGetMemoryFdPropertiesKHR");
    if (!fd_properties)
        return VK_ERROR_EXTENSION_NOT_PRESENT;
    VkExternalMemoryBufferCreateInfo external = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO,
                                                 .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT};
    VkBufferCreateInfo info = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .pNext = &external, .size = LATE_BYTES,
                               .usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT, .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    VkResult result = vkCreateBuffer(l->device, &info, NULL, buffer);
    if (result != VK_SUCCESS)
        return result;
    VkMemoryRequirements needs;
    vkGetBufferMemoryRequirements(l->device, *buffer, &needs);
    VkMemoryFdPropertiesKHR properties = {.sType = VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR};
    result = fd_properties(l->device, VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT, fd, &properties);
    if (result != VK_SUCCESS)
        return result;
    uint32_t bits = needs.memoryTypeBits & properties.memoryTypeBits;
    if (!bits)
        return VK_ERROR_FORMAT_NOT_SUPPORTED;
    uint32_t type = 0;
    while (!(bits & (1u << type)))
        type++;
    int own = dup(fd);
    VkImportMemoryFdInfoKHR import = {.sType = VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR, .handleType = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT,
                                      .fd = own};
    VkMemoryAllocateInfo allocate = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .pNext = &import, .allocationSize = needs.size,
                                     .memoryTypeIndex = type};
    result = vkAllocateMemory(l->device, &allocate, NULL, memory);
    if (result != VK_SUCCESS) {
        close(own);
        return result;
    }
    return vkBindBufferMemory(l->device, *buffer, *memory, 0);
}

/* The GPU copies src into the cleared host buffer; the share of words holding the CPU's word. */
static VkResult copy_share(struct late *l, VkBuffer src, long *share)
{
    LOAD(vkAllocateCommandBuffers);
    LOAD(vkFreeCommandBuffers);
    LOAD(vkBeginCommandBuffer);
    LOAD(vkEndCommandBuffer);
    LOAD(vkCmdCopyBuffer);
    LOAD(vkCmdPipelineBarrier);
    LOAD(vkCreateFence);
    LOAD(vkDestroyFence);
    LOAD(vkQueueSubmit);
    LOAD(vkWaitForFences);
    LOAD(vkFlushMappedMemoryRanges);
    LOAD(vkInvalidateMappedMemoryRanges);
    VkMappedMemoryRange range = {.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = l->host_memory, .offset = 0, .size = VK_WHOLE_SIZE};
    memset(l->mapped, 0, LATE_BYTES);
    VkResult result;
    if (!l->coherent && (result = vkFlushMappedMemoryRanges(l->device, 1, &range)) != VK_SUCCESS)
        return result;
    VkCommandBufferAllocateInfo command_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, .commandPool = l->pool,
                                                .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1};
    VkCommandBuffer commands;
    if ((result = vkAllocateCommandBuffers(l->device, &command_info, &commands)) != VK_SUCCESS)
        return result;
    VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
    VkBufferCopy region = {.size = LATE_BYTES};
    VkMemoryBarrier barrier = {.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER, .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
                               .dstAccessMask = VK_ACCESS_HOST_READ_BIT};
    VkFenceCreateInfo fence_info = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VkFence fence = VK_NULL_HANDLE;
    VkSubmitInfo submit = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &commands};
    if ((result = vkBeginCommandBuffer(commands, &begin)) == VK_SUCCESS) {
        vkCmdCopyBuffer(commands, src, l->host, 1, &region);
        vkCmdPipelineBarrier(commands, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &barrier, 0, NULL, 0, NULL);
        if ((result = vkEndCommandBuffer(commands)) == VK_SUCCESS && (result = vkCreateFence(l->device, &fence_info, NULL, &fence)) == VK_SUCCESS &&
            (result = vkQueueSubmit(l->queue, 1, &submit, fence)) == VK_SUCCESS &&
            (result = vkWaitForFences(l->device, 1, &fence, VK_TRUE, WAIT_NS)) == VK_SUCCESS &&
            (l->coherent || (result = vkInvalidateMappedMemoryRanges(l->device, 1, &range)) == VK_SUCCESS))
            *share = share_of(l->mapped);
    }
    if (fence != VK_NULL_HANDLE)
        vkDestroyFence(l->device, fence, NULL);
    vkFreeCommandBuffers(l->device, l->pool, 1, &commands);
    return result;
}

static int late_dmabuf(struct late *l, uint32_t family, const char *heap)
{
    LOAD(vkCreateBuffer);
    LOAD(vkGetBufferMemoryRequirements);
    LOAD(vkGetPhysicalDeviceMemoryProperties);
    LOAD(vkAllocateMemory);
    LOAD(vkBindBufferMemory);
    LOAD(vkMapMemory);
    LOAD(vkCreateCommandPool);
    int h = open(heap, O_RDONLY | O_CLOEXEC);
    if (h < 0) {
        printf("M19 GPU dmabuf FAIL heap open errno=%d\n", errno);
        return 1;
    }
    struct m19_heap_alloc alloc = {.len = LATE_BYTES, .fd_flags = O_RDWR | O_CLOEXEC};
    int failed = ioctl(h, M19_HEAP_ALLOC, &alloc);
    close(h);
    if (failed) {
        printf("M19 GPU dmabuf FAIL heap alloc errno=%d\n", errno);
        return 1;
    }
    int fd = (int)alloc.fd;
    uint32_t *cpu = mmap(NULL, LATE_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (cpu == MAP_FAILED) {
        printf("M19 GPU dmabuf FAIL map errno=%d\n", errno);
        return 1;
    }
    /* The host buffer the GPU copies into. */
    VkBufferCreateInfo host_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .size = LATE_BYTES, .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                    .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    VkResult result = vkCreateBuffer(l->device, &host_info, NULL, &l->host);
    if (result != VK_SUCCESS)
        return fail("dmabuf host buffer", result);
    VkMemoryRequirements needs;
    vkGetBufferMemoryRequirements(l->device, l->host, &needs);
    VkPhysicalDeviceMemoryProperties memory;
    vkGetPhysicalDeviceMemoryProperties(l->chosen, &memory);
    uint32_t type = UINT32_MAX;
    for (uint32_t i = 0; i < memory.memoryTypeCount && type == UINT32_MAX; i++)
        if ((needs.memoryTypeBits & (1u << i)) && (memory.memoryTypes[i].propertyFlags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT))
            type = i;
    if (type == UINT32_MAX)
        return fail("dmabuf host memory", VK_ERROR_FEATURE_NOT_PRESENT);
    l->coherent = (memory.memoryTypes[type].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
    VkMemoryAllocateInfo allocate = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = needs.size, .memoryTypeIndex = type};
    void *mapped;
    if ((result = vkAllocateMemory(l->device, &allocate, NULL, &l->host_memory)) != VK_SUCCESS ||
        (result = vkBindBufferMemory(l->device, l->host, l->host_memory, 0)) != VK_SUCCESS ||
        (result = vkMapMemory(l->device, l->host_memory, 0, VK_WHOLE_SIZE, 0, &mapped)) != VK_SUCCESS)
        return fail("dmabuf host memory", result);
    l->mapped = mapped;
    VkCommandPoolCreateInfo pool_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = family};
    if ((result = vkCreateCommandPool(l->device, &pool_info, NULL, &l->pool)) != VK_SUCCESS)
        return fail("dmabuf command pool", result);

    /* Imported first, as the X server imports a program's buffer before the program draws into it. */
    VkBuffer first, second;
    VkDeviceMemory first_memory, second_memory;
    if ((result = import_dmabuf(l, fd, &first, &first_memory)) != VK_SUCCESS)
        return fail("dmabuf import", result);
    struct m19_dmabuf_sync sync = {.flags = 2u};
    (void)ioctl(fd, M19_DMABUF_SYNC, &sync);
    for (uint32_t i = 0; i < LATE_BYTES / 4u; i++)
        cpu[i] = LATE_WORD;
    sync.flags = 2u | 4u;
    (void)ioctl(fd, M19_DMABUF_SYNC, &sync);
    long late = -1, again = -1, first_again = -1;
    if ((result = copy_share(l, first, &late)) != VK_SUCCESS)
        return fail("dmabuf copy", result);
    if ((result = import_dmabuf(l, fd, &second, &second_memory)) != VK_SUCCESS)
        return fail("dmabuf import again", result);
    if ((result = copy_share(l, second, &again)) != VK_SUCCESS || (result = copy_share(l, first, &first_again)) != VK_SUCCESS)
        return fail("dmabuf copy again", result);
    printf("M19 GPU dmabuf cpu=%ld late=%ld again=%ld first=%ld\n", share_of(cpu), late, again, first_again);
    munmap(cpu, LATE_BYTES);
    close(fd);
    printf("M19 GPU dmabuf ok\n");
    return 0;
}

static int usable(const VkPhysicalDeviceProperties *p, int allow_cpu)
{
    if (p->deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU)
        return allow_cpu;
    return p->vendorID == ADRENO_VENDOR;
}

int main(int argc, char **argv)
{
    /* vulkan [--allow-cpu], or (R4m) dmabuf HEAP [--allow-cpu]. */
    int dmabuf = argc >= 3 && !strcmp(argv[1], "dmabuf");
    int base = dmabuf ? 3 : 2;
    int allow_cpu = argc == base + 1 && !strcmp(argv[base], "--allow-cpu");
    if (argc < 2 || (!dmabuf && strcmp(argv[1], "vulkan")) || argc > base + 1 || (argc == base + 1 && !allow_cpu)) {
        fprintf(stderr, "usage: m19-gpu-probe vulkan|dmabuf HEAP [--allow-cpu]\n");
        return 64;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    void *loader = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!loader) {
        printf("M19 GPU vulkan FAIL loader %s\n", dlerror());
        return 1;
    }
    gipa = (PFN_vkGetInstanceProcAddr)dlsym(loader, "vkGetInstanceProcAddr");
    if (!gipa)
        return fail("vkGetInstanceProcAddr", VK_ERROR_INITIALIZATION_FAILED);

    LOAD(vkCreateInstance);
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO, .pApplicationName = "m19-gpu-probe", .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo instance_info = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app};
    VkResult result = vkCreateInstance(&instance_info, NULL, &instance);
    if (result != VK_SUCCESS)
        return fail("instance", result);

    LOAD(vkDestroyInstance);
    LOAD(vkEnumeratePhysicalDevices);
    LOAD(vkGetPhysicalDeviceProperties);
    LOAD(vkGetPhysicalDeviceProperties2);
    LOAD(vkGetPhysicalDeviceQueueFamilyProperties);
    LOAD(vkGetPhysicalDeviceMemoryProperties);
    LOAD(vkCreateDevice);
    LOAD(vkDestroyDevice);
    LOAD(vkGetDeviceQueue);
    LOAD(vkCreateBuffer);
    LOAD(vkDestroyBuffer);
    LOAD(vkGetBufferMemoryRequirements);
    LOAD(vkAllocateMemory);
    LOAD(vkFreeMemory);
    LOAD(vkBindBufferMemory);
    LOAD(vkMapMemory);
    LOAD(vkFlushMappedMemoryRanges);
    LOAD(vkInvalidateMappedMemoryRanges);
    LOAD(vkCreateCommandPool);
    LOAD(vkDestroyCommandPool);
    LOAD(vkAllocateCommandBuffers);
    LOAD(vkBeginCommandBuffer);
    LOAD(vkEndCommandBuffer);
    LOAD(vkCmdFillBuffer);
    LOAD(vkCmdPipelineBarrier);
    LOAD(vkCreateFence);
    LOAD(vkDestroyFence);
    LOAD(vkQueueSubmit);
    LOAD(vkWaitForFences);

    uint32_t count = MAX_DEVICES;
    VkPhysicalDevice devices[MAX_DEVICES];
    result = vkEnumeratePhysicalDevices(instance, &count, devices);
    if (result != VK_SUCCESS && result != VK_INCOMPLETE)
        return fail("enumerate", result);
    printf("M19 GPU vulkan devices=%u\n", count);

    /* Exactly one usable device: with the loader limited to Turnip's manifest there is one Adreno. */
    VkPhysicalDevice chosen = VK_NULL_HANDLE;
    VkPhysicalDeviceProperties properties;
    memset(&properties, 0, sizeof(properties));
    unsigned usable_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        VkPhysicalDeviceProperties p;
        vkGetPhysicalDeviceProperties(devices[i], &p);
        if (!usable(&p, allow_cpu))
            continue;
        usable_count++;
        chosen = devices[i];
        properties = p;
    }
    if (usable_count != 1)
        return fail(usable_count ? "several devices" : "no device", VK_ERROR_INCOMPATIBLE_DRIVER);
    VkPhysicalDeviceDriverProperties driver = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES};
    VkPhysicalDeviceProperties2 properties2 = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2};
    if (properties.apiVersion >= VK_API_VERSION_1_2)
        properties2.pNext = &driver;
    vkGetPhysicalDeviceProperties2(chosen, &properties2);
    printf("M19 GPU vulkan device=%s\n", properties.deviceName);
    printf("M19 GPU vulkan vendor=0x%04x type=%d driver=%d api=%u.%u.%u info=%s\n", properties.vendorID, (int)properties.deviceType,
           (int)driver.driverID, VK_API_VERSION_MAJOR(properties.apiVersion), VK_API_VERSION_MINOR(properties.apiVersion),
           VK_API_VERSION_PATCH(properties.apiVersion), driver.driverInfo[0] ? driver.driverInfo : "none");

    VkQueueFamilyProperties families[16];
    uint32_t family_count = 16, family = UINT32_MAX;
    vkGetPhysicalDeviceQueueFamilyProperties(chosen, &family_count, families);
    for (uint32_t i = 0; i < family_count && family == UINT32_MAX; i++)
        if (families[i].queueCount && (families[i].queueFlags & (VK_QUEUE_GRAPHICS_BIT | VK_QUEUE_COMPUTE_BIT | VK_QUEUE_TRANSFER_BIT)))
            family = i;
    if (family == UINT32_MAX)
        return fail("queue family", VK_ERROR_FEATURE_NOT_PRESENT);

    float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, .queueFamilyIndex = family, .queueCount = 1,
                                          .pQueuePriorities = &priority};
    static const char *const dmabuf_extensions[] = {"VK_KHR_external_memory_fd", "VK_EXT_external_memory_dma_buf"};
    VkDeviceCreateInfo device_info = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, .queueCreateInfoCount = 1, .pQueueCreateInfos = &queue_info,
                                      .enabledExtensionCount = dmabuf ? 2u : 0u, .ppEnabledExtensionNames = dmabuf ? dmabuf_extensions : NULL};
    VkDevice device;
    result = vkCreateDevice(chosen, &device_info, NULL, &device);
    if (result != VK_SUCCESS)
        return fail("device", result);
    VkQueue queue;
    vkGetDeviceQueue(device, family, 0, &queue);
    if (dmabuf) {
        struct late l = {.chosen = chosen, .device = device, .queue = queue};
        return late_dmabuf(&l, family, argv[2]);
    }

    VkBufferCreateInfo buffer_info = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .size = FILL_BYTES, .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT,
                                      .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    VkBuffer buffer;
    result = vkCreateBuffer(device, &buffer_info, NULL, &buffer);
    if (result != VK_SUCCESS)
        return fail("buffer", result);
    VkMemoryRequirements needs;
    vkGetBufferMemoryRequirements(device, buffer, &needs);
    VkPhysicalDeviceMemoryProperties memory;
    vkGetPhysicalDeviceMemoryProperties(chosen, &memory);
    /* Host-visible memory, coherent when the device offers it. */
    uint32_t type = UINT32_MAX;
    for (int pass = 0; pass < 2 && type == UINT32_MAX; pass++) {
        VkMemoryPropertyFlags want = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | (pass ? 0 : VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        for (uint32_t i = 0; i < memory.memoryTypeCount && type == UINT32_MAX; i++)
            if ((needs.memoryTypeBits & (1u << i)) && (memory.memoryTypes[i].propertyFlags & want) == want)
                type = i;
    }
    if (type == UINT32_MAX)
        return fail("memory type", VK_ERROR_FEATURE_NOT_PRESENT);
    int coherent = (memory.memoryTypes[type].propertyFlags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
    VkMemoryAllocateInfo allocate = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = needs.size, .memoryTypeIndex = type};
    VkDeviceMemory backing;
    result = vkAllocateMemory(device, &allocate, NULL, &backing);
    if (result != VK_SUCCESS)
        return fail("allocate", result);
    result = vkBindBufferMemory(device, buffer, backing, 0);
    if (result != VK_SUCCESS)
        return fail("bind", result);
    void *mapped;
    result = vkMapMemory(device, backing, 0, VK_WHOLE_SIZE, 0, &mapped);
    if (result != VK_SUCCESS)
        return fail("map", result);
    VkMappedMemoryRange range = {.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, .memory = backing, .offset = 0, .size = VK_WHOLE_SIZE};
    /* The CPU's seed: a buffer the GPU never touched cannot pass. */
    memset(mapped, SEED_BYTE, FILL_BYTES);
    if (!coherent && (result = vkFlushMappedMemoryRanges(device, 1, &range)) != VK_SUCCESS)
        return fail("flush", result);

    VkCommandPoolCreateInfo pool_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = family};
    VkCommandPool pool;
    result = vkCreateCommandPool(device, &pool_info, NULL, &pool);
    if (result != VK_SUCCESS)
        return fail("command pool", result);
    VkCommandBufferAllocateInfo command_info = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, .commandPool = pool,
                                                .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1};
    VkCommandBuffer commands;
    result = vkAllocateCommandBuffers(device, &command_info, &commands);
    if (result != VK_SUCCESS)
        return fail("command buffer", result);
    VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, .flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
    result = vkBeginCommandBuffer(commands, &begin);
    if (result != VK_SUCCESS)
        return fail("begin", result);
    vkCmdFillBuffer(commands, buffer, 0, VK_WHOLE_SIZE, FILL_WORD);
    /* The GPU's writes become visible to the host only through this barrier and the fence. */
    VkMemoryBarrier barrier = {.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER, .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
                               .dstAccessMask = VK_ACCESS_HOST_READ_BIT};
    vkCmdPipelineBarrier(commands, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &barrier, 0, NULL, 0, NULL);
    result = vkEndCommandBuffer(commands);
    if (result != VK_SUCCESS)
        return fail("end", result);

    VkFenceCreateInfo fence_info = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VkFence fence;
    result = vkCreateFence(device, &fence_info, NULL, &fence);
    if (result != VK_SUCCESS)
        return fail("fence", result);
    VkSubmitInfo submit = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &commands};
    unsigned long long started = now_us();
    result = vkQueueSubmit(queue, 1, &submit, fence);
    if (result != VK_SUCCESS)
        return fail("submit", result);
    result = vkWaitForFences(device, 1, &fence, VK_TRUE, WAIT_NS);
    unsigned long long took = now_us() - started;
    if (result != VK_SUCCESS)
        return fail("wait", result);
    if (!coherent && (result = vkInvalidateMappedMemoryRanges(device, 1, &range)) != VK_SUCCESS)
        return fail("invalidate", result);

    const uint32_t *words = mapped;
    unsigned mismatches = 0;
    for (uint32_t i = 0; i < FILL_BYTES / 4u; i++)
        mismatches += words[i] != FILL_WORD;
    printf("M19 GPU vulkan fill bytes=%u us=%llu coherent=%d mismatches=%u\n", FILL_BYTES, took, coherent, mismatches);

    vkDestroyFence(device, fence, NULL);
    vkDestroyCommandPool(device, pool, NULL);
    vkDestroyBuffer(device, buffer, NULL);
    vkFreeMemory(device, backing, NULL);
    vkDestroyDevice(device, NULL);
    vkDestroyInstance(instance, NULL);
    if (mismatches)
        return fail("fill mismatch", VK_SUCCESS);
    printf("M19 GPU vulkan fill ok\n");
    return 0;
}

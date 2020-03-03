#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "taint.h"

#include "../jitter/compat_py23.h"
#include "../jitter/bn.h"
#include "../jitter/queue.h"
#include "../jitter/vm_mngr.h"
#include "../jitter/vm_mngr_py.h"
#include "../jitter/JitCore.h"

/* Taint setters/getters */
/* Colors */
struct taint_t*
taint_init_colors(uint64_t nb_colors, uint64_t nb_registers, uint32_t max_register_size)
{
    struct taint_t* taint_colors;

    taint_colors = malloc(sizeof(*taint_colors));
    if (taint_colors == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc taint_colors\n");
        exit(EXIT_FAILURE);
    }

    taint_colors->colors = malloc(nb_colors*sizeof(*taint_colors->colors));
    if (taint_colors->colors == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc taint_colors->colors\n");
        exit(EXIT_FAILURE);
    }

    taint_colors->nb_colors = nb_colors;
    taint_colors->nb_registers = nb_registers;
    taint_colors->max_register_size = max_register_size;

    uint64_t i;
    for (i = 0 ; i < nb_colors ; i++)
    {
        taint_colors->colors[i] = taint_init_color(nb_registers, max_register_size);
    }

    return taint_colors;
}

struct taint_color_t
taint_init_color(uint64_t nb_registers, uint32_t max_register_size)
{
    struct taint_color_t taint_analysis;

    taint_color_init_registers(&taint_analysis, nb_registers);
    taint_color_init_memory(&taint_analysis);

    taint_analysis.callback_info = taint_init_callback_info(nb_registers,
                                                            max_register_size);
    return taint_analysis;
}

void
taint_check_color(uint64_t color_index, uint64_t nb_colors)
{
    if (color_index >= nb_colors)
    {
        fprintf(stderr,
            "TAINT: color %"PRIu64" does not exist\n",
            color_index);
        exit(EXIT_FAILURE);
    }
}

void
taint_check_register(uint64_t register_index,
                     struct interval interval,
                     uint64_t nb_registers,
                     uint32_t max_register_size)
{
    if (register_index >= nb_registers)
    {
        fprintf(stderr,
            "TAINT: register %"PRIu64" does not exist\n",
            register_index);
        exit(EXIT_FAILURE);
    }
    if (interval.start >= max_register_size)
    {
        fprintf(stderr,
            "TAINT: register %"PRIu64" does not have more than "
            "%"PRIu32" bytes.\n You tried to start reading at "
            "byte %"PRIu64"(+1).\n",
            register_index,
            max_register_size,
            interval.start);
        exit(EXIT_FAILURE);
    }
    if (interval.last >= max_register_size)
    {
        fprintf(stderr,
            "TAINT: register %"PRIu64" does not have more than "
            "%"PRIu32" bytes.\n You tried to reading until byte "
            "%"PRIu64" (+1).\n",
            register_index,
            max_register_size,
            interval.last);
        exit(EXIT_FAILURE);
    }
    if (interval.last < interval.start)
    {
        fprintf(stderr,
            "TAINT: register %"PRIu64" -> You tried to read "
            "from byte %"PRIu64" to byte %"PRIu64"\n",
            register_index,
            interval.start,
            interval.last);
        exit(EXIT_FAILURE);
    }
}

/* Registers */
void
taint_register_generic_access(struct taint_t *colors,
                  uint64_t color_index,
                  uint64_t register_index,
                  struct interval interval,
                  uint32_t access_type
                  )
{
    if (access_type == ADD)
        interval_tree_add(colors->colors[color_index].registers[register_index],
                          interval);
    else if (access_type == REMOVE)
        interval_tree_sub(colors->colors[color_index].registers[register_index],
                          interval);
}

struct rb_root
taint_get_register_color(struct taint_t *colors,
             uint64_t color_index,
             uint64_t register_index,
             struct interval interval
             )
{
    return taint_get_register(colors->colors[color_index].registers,
                  register_index,
                  interval,
                  colors->max_register_size);
}

struct rb_root
taint_get_register(struct rb_root ** registers,
           uint64_t register_index,
           struct interval interval,
           uint32_t max_register_size
           )
{
    return interval_tree_intersection(registers[register_index], interval);
}

void
taint_color_init_registers(struct taint_color_t *color, uint64_t nb_registers)
{
    color->registers
        = calloc(nb_registers, sizeof(*color->registers));

    if (color->registers == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc color->registers\n");
        exit(EXIT_FAILURE);
    }


    uint64_t i;
    for(i = 0; i < nb_registers; i++)
    {
        color->registers[i] = calloc(1, sizeof(*color->registers[i]));
        if (color->registers[i] == NULL)
        {
            fprintf(stderr, "TAINT: cannot alloc color->registers[i]\n");
            exit(EXIT_FAILURE);
        }
    }
}

void
taint_color_init_memory(struct taint_color_t *color)
{
    color->memory = calloc(1, sizeof(*color->memory));

    if (color->memory == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc color->memory\n");
        exit(EXIT_FAILURE);
    }
}

void
taint_color_remove_all_registers(struct taint_t *colors, uint64_t color_index)
{
    uint64_t i;
    for(i = 0; i < colors->nb_registers; i++)
    {
        interval_tree_free(colors->colors[color_index].registers[i]);
        *(colors->colors[color_index].registers[i]) = interval_tree_new();
    }
}

void
taint_remove_all_registers(struct taint_t *colors)
{
       uint64_t color_index;
       for (color_index = 0 ; color_index < colors->nb_colors ; color_index++)
       {
               taint_color_remove_all_registers(colors, color_index);
       }
}

/* Memory */
void
taint_memory_generic_access(struct taint_t *colors,
                            uint64_t color_index,
                            struct interval interval,
                            uint32_t access_type)
{
    if (access_type == ADD)
        interval_tree_add(colors->colors[color_index].memory,
                          interval);
    else if (access_type == REMOVE)
        interval_tree_sub(colors->colors[color_index].memory,
                          interval);
}

struct rb_root
taint_get_memory(struct taint_t *colors,
                 uint64_t color_index,
                 struct interval interval)
{
    return interval_tree_intersection(colors->colors[color_index].memory,
                                      interval);
}

void
taint_remove_all_memory(struct taint_t *colors)
{
    uint64_t i;
    for (i = 0; i < colors->nb_colors ; i++)
        taint_color_remove_all_memory(colors, i);
}

void
taint_color_remove_all_memory(struct taint_t *colors, uint64_t color_index)
{
    interval_tree_free(colors->colors[color_index].memory);
    *(colors->colors[color_index].memory) = interval_tree_new();
}


/* Callback info */
struct taint_callback_info_t *
taint_init_callback_info(uint64_t nb_registers, uint32_t max_register_size)
{
    // TODO
    struct taint_callback_info_t *callback_info;

    callback_info = malloc(sizeof(*callback_info));
        if (callback_info == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc "
                "taint_analysis->callback_info\n");
        exit(EXIT_FAILURE);
    }

    /* last tainted */
    /* Registers */
    callback_info->last_tainted.registers
        = calloc(nb_registers, sizeof(*callback_info->last_tainted.registers));

    if (callback_info->last_tainted.registers == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc "
                "callback_info->last_tainted.registers\n");
        exit(EXIT_FAILURE);
    }

    uint64_t index = 0;
    for( index = 0; index < nb_registers; index ++)
    {
        callback_info->last_tainted.registers[index] = calloc(1, sizeof(*callback_info->last_tainted.registers[index]));
    }

    /* Memory */
    callback_info->last_tainted.memory = calloc(1, sizeof(*callback_info->last_tainted.memory));

    /* last untainted */
    /* Registers */
    callback_info->last_untainted.registers
        = calloc(nb_registers, sizeof(*callback_info->last_untainted.registers));

    if (callback_info->last_untainted.registers == NULL)
    {
        fprintf(stderr, "TAINT: cannot alloc "
                "callback_info->last_untainted.registers\n");
        exit(EXIT_FAILURE);
    }

    for( index = 0; index < nb_registers; index ++)
    {
        callback_info->last_untainted.registers[index] = calloc(1, sizeof(*callback_info->last_untainted.registers[index]));
    }

    /* Memory */
    callback_info->last_untainted.memory = calloc(1, sizeof(*callback_info->last_untainted.memory));

    /* Exceptions for calbacks */
    callback_info->exception_flag = 0;

    return callback_info;
}

void
taint_clean_all_callback_info(struct taint_t *colors)
{
    uint64_t color_index;

    for(color_index = 0; color_index < colors->nb_colors ; color_index++)
    {
        taint_clean_callback_info(colors, color_index);
    }
}

void
taint_clean_callback_info(struct taint_t *colors, uint64_t color_index)
{
    uint64_t i = 0;
    for( i = 0; i < colors->nb_registers ; i++)
    {
        interval_tree_free(colors->colors[color_index].callback_info->last_tainted.registers[i]);
        //colors->colors[color_index].callback_info->last_tainted.registers[i] = calloc(1, sizeof(*colors->colors[color_index].callback_info->last_tainted.registers[i]));
        interval_tree_free(colors->colors[color_index].callback_info->last_untainted.registers[i]);
        //colors->colors[color_index].callback_info->last_untainted.registers[i] = calloc(1, sizeof(*colors->colors[color_index].callback_info->last_untainted.registers[i]));
    }
    interval_tree_free(colors->colors[color_index].callback_info->last_tainted.memory);
    //colors->colors[color_index].callback_info->last_tainted.memory = calloc(1, sizeof(*colors->colors[color_index].callback_info->last_tainted.memory));
    interval_tree_free(colors->colors[color_index].callback_info->last_untainted.memory);
    //colors->colors[color_index].callback_info->last_untainted.memory = calloc(1, sizeof(*colors->colors[color_index].callback_info->last_untainted.memory));
}

void
taint_update_memory_callback_info(struct taint_t *colors,
                                  uint64_t color_index,
                                  struct interval interval,
                                  int event_type)
{
    if (event_type == TAINT_EVENT)
        interval_tree_add(colors->colors[color_index].callback_info->last_tainted.memory,
                          interval);
    else if (event_type == UNTAINT_EVENT)
        interval_tree_add(colors->colors[color_index].callback_info->last_untainted.memory,
                          interval);
    else
    {
        fprintf(stderr,
            "TAINT: unknown event type %d\n"
            "\t-> Callback information are not updated !\n",
            event_type);
    }
}

void
taint_update_register_callback_info(struct taint_t *colors,
                                    uint64_t color_index,
                                    uint64_t register_index,
                                    struct interval interval,
                                    int event_type)
{
    if (event_type == TAINT_EVENT)
        interval_tree_add(colors->colors[color_index].callback_info->last_tainted.registers[register_index],
                          interval);
    else if (event_type == UNTAINT_EVENT)
        interval_tree_add(colors->colors[color_index].callback_info->last_untainted.registers[register_index],
                          interval);
}

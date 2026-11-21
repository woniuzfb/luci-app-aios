<script setup lang="ts">
defineProps<{
  modelValue?: boolean;
  label?: string;
}>();

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void;
}>();
</script>

<template>
  <label class="switch-label" @click.prevent="emit('update:modelValue', !modelValue)">
    <span class="switch-track" :class="{ on: !!modelValue }">
      <span class="switch-thumb" />
    </span>
    <span v-if="label">{{ label }}</span>
  </label>
</template>

/** components/stepper/StepClustering.vue: the cluster count is reported once,
 *  and only when the user changes it (each report re-runs clustering). */
import { shallowMount } from '@vue/test-utils'
import StepClustering from '~/components/stepper/StepClustering.vue'

function mountStep() {
  return shallowMount(StepClustering, {
    propsData: {
      noOfclusters: 4,
      noOfclustersList: [2, 3, 4, 5],
      fileType: 'json',
      allIps: [],
      selectedCluster: [],
      clusterHierarchy: [],
      headers: [],
      modularityData: [],
      elbowData: [],
    },
    stubs: ['NetworkGraph', 'ModularityChart'],
  })
}

describe('StepClustering cluster count', () => {
  test('a count set by the page is not reported back', async () => {
    const wrapper = mountStep()
    await wrapper.setProps({ noOfclusters: 3 })
    expect(wrapper.vm.localClusters).toBe(3)
    expect(wrapper.emitted('update:noOfclusters')).toBeUndefined()
  })

  test('a user change is reported exactly once', async () => {
    const wrapper = mountStep()
    wrapper.vm.localClusters = 5
    await wrapper.vm.$nextTick()
    await wrapper.vm.onClustersChange()
    expect(wrapper.emitted('update:noOfclusters')).toEqual([[5]])
  })
})
